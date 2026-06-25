// PM2 process definition for the TestPilot engine.
// NOTE: extension is .cjs (NOT .js) on purpose — package.json has "type":"module",
// so a .js config would be parsed as ESM and `module.exports` would throw, leaving
// the process unstarted. PM2 loads .cjs as CommonJS regardless of package type.
//
// Phase-1 [P0] Auto-Restart Policy:
//   - autorestart: restart on any crash (default, made explicit).
//   - max_memory_restart '500M': cap RSS so a memory leak can't take down the VM.
//   - instances 1 + fork mode: REQUIRED, not cluster. The engine holds in-memory
//     state (sessions Map, activeScans counter, platformMaps, globalBrain). Cluster
//     mode with >1 worker would fragment that state across processes. Single fork only.
//
// Apply on the VM:  pm2 start ecosystem.config.cjs && pm2 save
// (env/secrets come from ./.env via the app's own dotenv — not injected here.)
module.exports = {
  apps: [
    {
      name: 'testpilot',
      script: 'server.js',
      cwd: '/home/azureuser/testpilot',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
