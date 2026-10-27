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

# Resolve a Python that actually has this project's dependencies. A machine can
# have several Pythons on PATH (e.g. Homebrew python3 with nothing installed),
# and picking the wrong one crashes the engine in a 30s loop and leaves
# `uvicorn` unresolvable as a console script. The chosen interpreter must be
# able to import the API's core imports before we run anything.
PY=""
for cand in .venv/bin/python python3 /usr/bin/python3 python3.11; do
  command -v "$cand" >/dev/null 2>&1 || continue
  if "$cand" -c "import uvicorn, httpx, fastapi" >/dev/null 2>&1; then
    PY="$cand"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "[SUPERVISOR] no Python with uvicorn/httpx/fastapi found on PATH" >> engine_state.txt
  exit 1
fi

while true; do
  "$PY" -u outbound_engine.py >> engine_state.txt 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "[SUPERVISOR] engine stopped cleanly (HOLD gate) - not restarting." >> engine_state.txt
    break
  fi
  echo "[SUPERVISOR] engine crashed (rc=$rc) - restarting in 30s." >> engine_state.txt
  sleep 30
done &
exec "$PY" -m uvicorn api:app --host 0.0.0.0 --port 8080
