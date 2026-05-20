import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

// runMultiRole: kicks off N sequential scenario test runs (one per role)
// all tagged with the same multi_role_group_id. The roles execute in order
// because each /api/test call on Azure already runs the test in background;
// Multi-Role's value is the grouped view of results, not strict sequencing.
//
// Returns { multi_role_group_id, testRuns: [{testId, app, role.name}] }
// Frontend redirects to /history?group=<id> after this resolves.
Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

    const { appId, roles, apiKey } = await req.json();
    if (!appId || !Array.isArray(roles) || roles.length < 2) {
      return Response.json({ error: 'appId and at least 2 roles required' }, { status: 400 });
    }

    // Resolve the App entity by id from Base44 to validate ownership.
    const app = await base44.entities.App.get(appId);
    if (!app || app.owner_email !== user.email) {
      return Response.json({ error: 'App not found' }, { status: 404 });
    }

    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    // Use a UUID for the group so all role-runs are linked.
    const groupId = crypto.randomUUID();
    const testRuns = [];

    for (const role of roles) {
      if (!role.email || !role.password || !role.scenario?.trim()) continue;
      try {
        const azureRes = await fetch('https://testpilotapp.dev/api/test', {
          method: 'POST',
          headers: {
            'X-Base44-Auth': azureKey,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            appId: app.app_id,
            scenario: role.scenario,
            email: role.email,
            password: role.password,
            apiKey,
            userEmail: user.email,
          }),
        });
        if (!azureRes.ok) {
          const errBody = await azureRes.text();
          testRuns.push({ error: `Failed to start: ${errBody}`, role: role.name });
          continue;
        }
        const { testId } = await azureRes.json();
        const tr = await base44.entities.TestRun.create({
          test_id: testId,
          app: appId,
          kind: 'multi_role',
          scenario: `[${role.name}] ${role.scenario}`,
          status: 'running',
          owner_email: user.email,
          started_at: new Date().toISOString(),
          live_view_url: `https://testpilotapp.dev/live-test/${testId}`,
          multi_role_group_id: groupId,
        });
        testRuns.push({ testId, testRun: tr, role: role.name });
      } catch (e) {
        testRuns.push({ error: e.message, role: role.name });
      }
    }

    return Response.json({ multi_role_group_id: groupId, testRuns });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});
