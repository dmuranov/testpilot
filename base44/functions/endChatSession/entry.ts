import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { sessionId } = await req.json();

    const azureRes = await fetch(`https://testpilotapp.dev/api/chat/${sessionId}/end`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Base44-Auth': Deno.env.get('AZURE_BACKEND_KEY'),
      },
      body: JSON.stringify({ userEmail: user.email }),
    });

    if (azureRes.status === 404) {
      // Session already cleaned up by idle reaper — treat as success
      return Response.json({ ended: true, alreadyGone: true });
    }
    if (azureRes.status === 401) {
      return Response.json({ error: 'Azure backend auth failed — check AZURE_BACKEND_KEY' }, { status: 401 });
    }
    if (!azureRes.ok) {
      const errText = await azureRes.text();
      return Response.json({ error: `Azure error: ${errText}` }, { status: 500 });
    }

    return Response.json({ ended: true });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});