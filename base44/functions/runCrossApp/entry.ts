import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

const AZURE_BASE = 'https://testpilotapp.dev';

async function azurePost(path, body, azureKey) {
  const res = await fetch(`${AZURE_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Base44-Auth': azureKey,
    },
    body: JSON.stringify(body),
  });
  return res;
}

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const { appBlocks, scenario, mode, apiKey } = await req.json();

    // 1. Validate all apps belong to the current user
    const appMeta = {}; // appId -> { name, app_id }
    for (const block of appBlocks) {
      const matches = await base44.entities.App.filter({ app_id: block.appId, owner_email: user.email });
      if (!matches || matches.length === 0) {
        return Response.json({ error: `App ${block.appId} not found or not owned by you` }, { status: 404 });
      }
      appMeta[block.appId] = matches[0];
    }

    // 2. Start chat sessions for each role across all app blocks
    const sessionMap = {}; // "<role.name> @ <appName>" -> sessionId
    for (const block of appBlocks) {
      const appName = appMeta[block.appId]?.name || block.appId;
      for (const role of block.roles) {
        const startRes = await azurePost('/api/chat/start', {
          appId: block.appId,
          email: role.email || null,
          password: role.password || null,
          apiKey,
          userEmail: user.email,
          securityMode: false,
        }, azureKey);

        if (!startRes.ok) {
          const errText = await startRes.text();
          return Response.json({ error: `Failed to start session for role "${role.name}": ${errText}` }, { status: 500 });
        }
        const startData = await startRes.json();
        const key = `${role.name} @ ${appName}`;
        sessionMap[key] = startData.sessionId;
      }
    }

    // 3. Parse scenario into steps: [Role @ App] instruction
    const stepRegex = /\[([^\]]+)\]\s*(.+)/g;
    const steps = [];
    let match;
    while ((match = stepRegex.exec(scenario)) !== null) {
      steps.push({ roleKey: match[1].trim(), instruction: match[2].trim() });
    }

    // 4. Execute each step sequentially
    const stepResults = [];
    for (const step of steps) {
      const sessionId = sessionMap[step.roleKey];
      if (!sessionId) {
        stepResults.push(`**[${step.roleKey}]** ❌ No session found for this role`);
        continue;
      }

      const msgRes = await azurePost(`/api/chat/${sessionId}/message`, {
        message: step.instruction,
        apiKey,
        userEmail: user.email,
      }, azureKey);

      if (!msgRes.ok) {
        const errText = await msgRes.text();
        stepResults.push(`**[${step.roleKey}]** ❌ ${errText}`);
      } else {
        const msgData = await msgRes.json();
        const reply = msgData.reply || msgData.message || 'Done';
        stepResults.push(`**[${step.roleKey}]** ✅ ${reply}`);
      }
    }

    // 5. Close all sessions
    for (const [, sessionId] of Object.entries(sessionMap)) {
      await azurePost(`/api/chat/${sessionId}/end`, { userEmail: user.email }, azureKey).catch(() => {});
    }

    // 6. Build summary and create TestRun entity.
    // Base44 entity relations are keyed by the entity's internal `id`,
    // not by custom fields like `app_id`. appMeta[<azureAppId>] is the
    // resolved App entity from the ownership check in step 1 — use its
    // `.id` so TestRun.app actually links back to a real App row
    // (history / app-detail filters depend on this).
    const summaryMd = stepResults.join('\n\n');
    const primaryApp = appMeta[appBlocks[0]?.appId];
    const testRun = await base44.entities.TestRun.create({
      test_id: `crossapp-${Date.now()}`,
      app: primaryApp?.id || '',
      kind: 'crossapp',
      status: 'completed',
      scenario,
      summary_md: summaryMd,
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      owner_email: user.email,
    });

    return Response.json({ testRun, sessionMap });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});