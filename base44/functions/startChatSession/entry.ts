import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { appId, email, password, apiKey } = await req.json();

    const azureRes = await fetch('https://testpilotapp.dev/api/chat/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Base44-Auth': Deno.env.get('AZURE_BACKEND_KEY'),
      },
      body: JSON.stringify({
        appId,
        email: email || null,
        password: password || null,
        apiKey,
        userEmail: user.email,
        securityMode: false,
      }),
    });

    if (azureRes.status === 401) {
      return Response.json({ error: 'Azure backend auth failed — check AZURE_BACKEND_KEY' }, { status: 401 });
    }
    if (azureRes.status === 402) {
      return Response.json({ error: 'This feature requires a paid plan' }, { status: 402 });
    }
    if (azureRes.status === 404) {
      return Response.json({ error: 'App not found on Azure backend' }, { status: 404 });
    }
    if (!azureRes.ok) {
      const errText = await azureRes.text();
      return Response.json({ error: `Azure error: ${errText}` }, { status: 500 });
    }

    const data = await azureRes.json();
    return Response.json({ sessionId: data.sessionId, screenshot: data.screenshot, url: data.url, loggedIn: data.loggedIn });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});