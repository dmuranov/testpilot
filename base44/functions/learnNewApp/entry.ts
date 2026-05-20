import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const payload = await req.json();
    const { url, email, password, description, apiKey, freeRun } = payload;

    // Call Azure backend
    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const azureRes = await fetch('https://testpilotapp.dev/api/learn', {
      method: 'POST',
      headers: {
        'X-Base44-Auth': azureKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url,
        email: email || null,
        password: password || null,
        description,
        apiKey,
        freeRun,
        userEmail: user.email
      })
    });

    if (!azureRes.ok) {
      const err = await azureRes.text();
      return Response.json({ error: err }, { status: azureRes.status });
    }

    const { appId, status } = await azureRes.json();

    // Create App entity in Base44
    const appName = new URL(url).hostname.replace('www.', '').split('.')[0];
    const app = await base44.entities.App.create({
      app_id: appId,
      name: appName,
      url,
      description,
      owner_email: user.email,
      status
    });

    return Response.json({ appId, app, status });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});