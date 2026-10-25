#!/usr/bin/env bash
# Replit run entrypoint: keep the outbound engine alive, then serve the API.
#
# The supervisor only restarts the engine after a CRASH (non-zero exit).
# A clean exit means the startup healthcheck returned HOLD - the gate that
# stops us mailing leads on a dead sender - so we must not retry: retrying
# would send a probe email every 30 seconds.
set -u
if [ -f engine_state.txt ] && [ "$(wc -c < engine_state.txt)" -gt 1000000 ]; then
  mv -f engine_state.txt engine_state.old.log
fi
while true; do
  python3 -u outbound_engine.py >> engine_state.txt 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "[SUPERVISOR] engine stopped cleanly (HOLD gate) - not restarting." >> engine_state.txt
    break
  fi
  echo "[SUPERVISOR] engine crashed (rc=$rc) - restarting in 30s." >> engine_state.txt
  sleep 30
done &
exec uvicorn api:app --host 0.0.0.0 --port 8080
