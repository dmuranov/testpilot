// PM2 process definition for the TestPilot engine.
// NOTE: extension is .cjs (NOT .js) on purpose — package.json has "type":"module",
// so a .js config would be parsed as ESM and `module.exports` would throw, leaving
// the process unstarted. PM2 loads .cjs as CommonJS regardless of package type.
//
// Phase-1 [P0] Auto-Restart Policy:
//   - autorestart: restart on any crash (default, made explicit).
//   - max_memory_restart '1800M': cap RSS so a real leak can't take down the VM,
//     but high enough to fit MAX_CONCURRENT_SCANS (3) headless Chromium instances
//     on this 3.8 GB box. The old 500M cap OOM-killed the process mid-scan whenever
//     2-3 scans ran at once (each Chromium ~200-350M) — restarting killed every
//     in-flight scan. 1800M leaves ~2 GB for the OS + page cache.
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
      max_memory_restart: '1800M',
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
