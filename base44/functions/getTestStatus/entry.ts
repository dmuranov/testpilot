import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const payload = await req.json();
    const { testId } = payload;

    // Call Azure backend
    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const azureRes = await fetch(`https://testpilotapp.dev/api/test/${testId}`, {
      method: 'GET',
      headers: {
        'X-Base44-Auth': azureKey
      }
    });

    if (!azureRes.ok) {
      const err = await azureRes.text();
      return Response.json({ error: err }, { status: azureRes.status });
    }

    const testData = await azureRes.json();

    // Update TestRun entity if it exists
    const testRuns = await base44.entities.TestRun.filter({ test_id: testId });
    if (testRuns && testRuns.length > 0) {
      const updateData = {
        status: testData.status,
        steps_total: testData.steps?.length || 0,
        steps_passed: testData.steps?.filter(s => s.passed)?.length || 0,
        steps_failed: testData.steps?.filter(s => !s.passed)?.length || 0,
        bugs_count: testData.bugs?.length || 0,
        summary_md: testData.summary,
        bugs_json: testData.bugs
      };

      if (testData.status !== 'running') {
        updateData.finished_at = new Date().toISOString();
      }

      await base44.entities.TestRun.update(testRuns[0].id, updateData);
    }

    return Response.json(testData);
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});