import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const payload = await req.json();
    const { apiKey } = payload;

    // Call Azure backend to verify
    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const azureRes = await fetch('https://testpilotapp.dev/api/utils/verify-anthropic-key', {
      method: 'POST',
      headers: {
        'X-Base44-Auth': azureKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ apiKey })
    });

    const result = await azureRes.json();
    return Response.json(result);
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});