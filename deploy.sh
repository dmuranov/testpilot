#!/usr/bin/env bash
# Push-to-deploy: fetch origin/main and reload PM2 — but DRAIN active scans first
# so a deploy never kills an in-flight client scan (honors the no-kill rule).
# Run by CI via a restricted forced-command SSH key, or manually: bash deploy.sh
set -euo pipefail
cd /home/azureuser/testpilot
log(){ echo "[deploy $(date -u +%H:%M:%S)] $*"; }
for i in $(seq 1 60); do
  AS=$(curl -s --max-time 5 http://localhost:3001/api/health | node -e "let d=\"\";process.stdin.on(\"data\",c=>d+=c).on(\"end\",()=>{try{console.log(JSON.parse(d).activeScans||0)}catch{console.log(0)}})" 2>/dev/null || echo 0)
  [ "$AS" = "0" ] && break
  log "waiting for $AS active scan(s) to drain… ($i/60)"; sleep 5
done
git fetch --quiet origin main
log "deploying origin/main @ $(git rev-parse --short origin/main) (was $(git rev-parse --short HEAD))"
git reset --hard origin/main
pm2 reload testpilot >/dev/null 2>&1 || pm2 restart testpilot >/dev/null 2>&1
log "done. health: $(curl -s --max-time 8 http://localhost:3001/api/health | head -c 70)"
