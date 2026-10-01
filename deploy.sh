#!/usr/bin/env bash
# Push-to-deploy: fetch origin/main and reload PM2 — but DRAIN active scans first
# so a deploy never kills an in-flight client scan (honors the no-kill rule).
# Run by CI via a restricted forced-command SSH key, or manually: bash deploy.sh
set -euo pipefail
cd /home/azureuser/testpilot
log(){ echo "[deploy $(date -u +%H:%M:%S)] $*"; }
# health_field <field> <fallback>: one JSON field from /api/health, never fails the script.
health_field(){ (curl -s --max-time 5 http://localhost:3001/api/health || true) | node -e "let d=\"\";process.stdin.on(\"data\",c=>d+=c).on(\"end\",()=>{try{const v=JSON.parse(d)[\"$1\"];console.log(v===undefined?\"$2\":v)}catch{console.log(\"$2\")}})" 2>/dev/null || echo "$2"; }
# Unknown (server down / health 500) is not "zero scans": wait through a
# transient blip, but a server that cannot answer for 30s has nothing to
# drain — a crash-looping box must not hold a hotfix for five minutes.
UNKNOWN=0
for i in $(seq 1 60); do
  AS=$(health_field activeScans "?")
  [ "$AS" = "0" ] && break
  if [ "$AS" = "?" ]; then
    UNKNOWN=$((UNKNOWN+1)); [ "$UNKNOWN" -ge 6 ] && { log "health not answering for 30s — nothing to drain, deploying"; break; }
  else
    UNKNOWN=0
  fi
  log "waiting for $AS active scan(s) to drain… ($i/60)"; sleep 5
done
git fetch --quiet origin main
log "deploying origin/main @ $(git rev-parse --short origin/main) (was $(git rev-parse --short HEAD))"
git reset --hard origin/main
# Start or reload FROM THE ECOSYSTEM FILE so NODE_ENV=production (and the
# xvfb DISPLAY) are always applied, however the process was first started.
# A bare "pm2 reload testpilot" keeps whatever env the process was born with.
pm2 startOrReload ecosystem.config.cjs --only testpilot --update-env >/dev/null 2>&1 || pm2 restart testpilot --update-env >/dev/null 2>&1
pm2 save >/dev/null 2>&1 || true   # persist the (possibly repaired) env so a VM reboot resurrects it
# The server must come up in PRODUCTION mode (NODE_ENV=production from
# ecosystem.config.cjs). In local mode it sends no mail and runs no jobs, so a
# process started with a bare "pm2 start server.js" would silently go quiet.
MODE=""
for i in $(seq 1 30); do   # up to ~3.5 min worst case (2s sleep + 5s curl timeout per try)
  MODE=$(health_field runMode "")
  [ -n "$MODE" ] && break
  sleep 2
done
log "done. status: $(health_field status unknown) connectivity: $(health_field connectivity unknown) activeScans: $(health_field activeScans '?')"
log "run mode: ${MODE:-unknown}"
# A clear non-production answer is a failed deploy (the server is up but would
# send no mail and run no jobs). No answer within the wait is logged, not
# failed: a slow boot or a transient health 500 must not turn a good deploy red.
if [ -n "$MODE" ] && [ "$MODE" != "production" ]; then
  log "ERROR: server is running in ${MODE} mode, not production. Fix: pm2 delete testpilot && pm2 start ecosystem.config.cjs && pm2 save"
  exit 1
fi
if [ -z "$MODE" ]; then
  log "WARNING: health gave no run mode within the wait — check pm2 logs"
fi
exit 0
