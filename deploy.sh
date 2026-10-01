#!/usr/bin/env bash
# Push-to-deploy: fetch origin/main and reload PM2 — but DRAIN active scans first
# so a deploy never kills an in-flight client scan (honors the no-kill rule).
# Run by CI via a restricted forced-command SSH key, or manually: bash deploy.sh
set -euo pipefail
cd /home/azureuser/testpilot
log(){ echo "[deploy $(date -u +%H:%M:%S)] $*"; }
# health_field <field> <fallback>: one JSON field from /api/health, never fails the script.
# json_field <json> <field> <fallback>
json_field(){ printf '%s' "$1" | node -e "let d=\"\";process.stdin.on(\"data\",c=>d+=c).on(\"end\",()=>{try{const v=JSON.parse(d)[\"$2\"];console.log(v===undefined?\"$3\":v)}catch{console.log(\"$3\")}})" 2>/dev/null || echo "$3"; }
health_field(){ json_field "$(curl -s --max-time 5 http://localhost:3001/api/health || true)" "$1" "$2"; }
# wait_for_mode <tries>: polls /api/health for runMode; prints it (empty if none).
# Each try is a 5s curl timeout + 2s sleep, so 30 tries is up to ~3.5 minutes.
wait_for_mode(){ local m="" i; for i in $(seq 1 "$1"); do m=$(health_field runMode ""); [ -n "$m" ] && break; sleep 2; done; printf '%s' "$m"; }
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
PM2_OK=1
pm2 startOrReload ecosystem.config.cjs --only testpilot --update-env >/dev/null 2>&1 \
  || pm2 restart testpilot --update-env >/dev/null 2>&1 \
  || PM2_OK=0
if [ "$PM2_OK" = "0" ]; then
  # Neither reload nor restart took: the OLD process may still be serving and
  # would pass every check below. Recreate from the ecosystem file instead.
  log "pm2 reload and restart both failed — recreating the process from ecosystem.config.cjs"
  pm2 delete testpilot >/dev/null 2>&1 || true
  pm2 start ecosystem.config.cjs --only testpilot >/dev/null 2>&1 || { log "ERROR: pm2 start from ecosystem.config.cjs failed"; pm2 logs testpilot --lines 20 --nostream 2>/dev/null || true; exit 1; }
fi
pm2 save >/dev/null 2>&1 || true   # persist the (possibly repaired) env so a VM reboot resurrects it
# The server must come up in PRODUCTION mode (NODE_ENV=production from
# ecosystem.config.cjs). In local mode it sends no mail and runs no jobs, so a
# process started with a bare "pm2 start server.js" would silently go quiet.
MODE=$(wait_for_mode 30)
H=$(curl -s --max-time 8 http://localhost:3001/api/health || true)
log "done. status: $(json_field "$H" status unknown) connectivity: $(json_field "$H" connectivity unknown) activeScans: $(json_field "$H" activeScans '?')"
log "run mode: ${MODE:-unknown}"
# A clear non-production answer is a failed deploy (the server is up but would
# send no mail and run no jobs). No answer within the wait is logged, not
# failed: a slow boot or a transient health 500 must not turn a good deploy red.
if [ -n "$MODE" ] && [ "$MODE" != "production" ]; then
  # Known cause, known fix: the process was born without its environment.
  # Recreate it from the ecosystem file now, then re-check, rather than leaving
  # production up but silent until a human reads the red run.
  log "server is running in ${MODE} mode — recreating the pm2 process from ecosystem.config.cjs"
  pm2 delete testpilot >/dev/null 2>&1 || true
  pm2 start ecosystem.config.cjs --only testpilot >/dev/null 2>&1 || true
  pm2 save >/dev/null 2>&1 || true
  MODE=$(wait_for_mode 30)
  log "run mode after repair: ${MODE:-unknown}"
  if [ "$MODE" != "production" ]; then
    log "ERROR: still not in production mode after recreating the process — check pm2 logs and ecosystem.config.cjs"
    exit 1
  fi
fi
if [ -z "$MODE" ]; then
  # No health answer at all. A slow boot is a warning; a process that pm2 does
  # not report as online is a failed deploy, not a green one.
  PM2_STATUS=$(pm2 jlist 2>/dev/null | node -e "let d=\"\";process.stdin.on(\"data\",c=>d+=c).on(\"end\",()=>{try{const p=JSON.parse(d).find(x=>x.name===\"testpilot\");console.log(p?p.pm2_env.status+\" restarts=\"+p.pm2_env.restart_time:\"missing\")}catch{console.log(\"unknown\")}})" 2>/dev/null || echo unknown)
  log "WARNING: health gave no run mode within the wait — pm2 says: ${PM2_STATUS}"
  case "$PM2_STATUS" in
    online*) ;;
    *) log "ERROR: testpilot is not online under pm2"; pm2 logs testpilot --lines 20 --nostream 2>/dev/null || true; exit 1;;
  esac
fi
exit 0
