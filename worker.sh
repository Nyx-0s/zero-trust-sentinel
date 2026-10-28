#!/usr/bin/env bash
# =============================================================================
# Zero-Trust Sentinel - Background Worker entrypoint (Render "Worker" service)
#
# Web Services answer HTTP; this process runs 24/7 and owns everything that
# must keep running without a request:
#   1. outbound_engine.py  - the "Voice": permission-based follow-up emails
#   2. harvey run          - the "Brain": discovery loop (needs ANTHROPIC_API_KEY)
#   3. win_back_cron.py    - daily lifecycle/win-back pass (Render has no user
#                            crontab, so the always-on worker runs it itself)
#
# Used on Render via `dockerCommand: bash worker.sh` in render.yaml. Works
# locally too: docker run --rm --env-file .env zero-trust-sentinel bash worker.sh
#
# Graceful by design: SKIP_HARVEY=1 (or a missing key/CLI) runs outbound-only
# instead of crashing the container.
# =============================================================================
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
log() { echo "[worker $(date '+%H:%M:%S')] $*"; }

trap 'log "shutting down"; kill 0' SIGTERM SIGINT

# --- 1. The Voice: outbound engine -----------------------------------------
log "starting outbound_engine.py"
python outbound_engine.py &
ENGINE_PID=$!

# --- 2. The Brain: harvey discovery loop -----------------------------------
if [ "${SKIP_HARVEY:-0}" = "1" ]; then
    log "SKIP_HARVEY=1 - harvey disabled"
elif ! command -v harvey >/dev/null 2>&1; then
    log "harvey CLI not installed - running outbound-only"
elif [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    log "ANTHROPIC_API_KEY not set - running outbound-only"
elif ! command -v claude >/dev/null 2>&1; then
    log "claude CLI not installed - running outbound-only"
else
    if [ -n "${SITE_URL:-}" ]; then
        log "training harvey on $SITE_URL"
        harvey train "$SITE_URL" >> harvey.log 2>&1 || log "harvey train failed (continuing)"
        harvey signals --confirm free >> harvey.log 2>&1 || log "harvey signals failed (continuing)"
    else
        log "SITE_URL not set - skipping 'harvey train'"
    fi
    log "starting harvey run loop"
    harvey run >> harvey.log 2>&1 &
    HARVEY_PID=$!
fi

# --- 2b. The Brain (Groq): hunter discovery loop ----------------------------
# hunter.py does harvey's job without the Claude/Anthropic CLI, so lead
# discovery runs HERE, on the server - no laptop, no ANTHROPIC_API_KEY.
# Gated exactly like harvey: a missing key or an empty target list logs why
# and skips, and it never takes the worker down.
if [ "${SKIP_HUNTER:-0}" = "1" ]; then
    log "SKIP_HUNTER=1 - hunter discovery disabled"
elif [ -z "${GROQ_API_KEY:-}" ]; then
    log "GROQ_API_KEY not set - hunter discovery skipped"
elif [ ! -s marketing/seed_leads.csv ]; then
    log "marketing/seed_leads.csv missing or empty - hunter discovery skipped"
else
    hunter_loop() {
        while true; do
            log "running hunter discovery pass"
            python hunter.py --api "${SITE_URL:-https://zerodaysentinel.xo.je}" \
                --limit "${HUNTER_LIMIT:-10}" >> hunter.log 2>&1 \
                || log "hunter pass failed (retrying after the interval)"
            sleep "${HUNTER_INTERVAL_SECONDS:-21600}"
        done
    }
    hunter_loop &
    HUNTER_PID=$!
    log "hunter discovery loop started (pid $HUNTER_PID, every ${HUNTER_INTERVAL_SECONDS:-21600}s)"
fi

# --- 3. Daily win-back pass -------------------------------------------------
win_back_loop() {
    while true; do
        log "running win_back_cron.py"
        python win_back_cron.py >> win_back.log 2>&1 || log "win_back_cron failed (will retry in 24h)"
        sleep 86400
    done
}
win_back_loop &

log "worker up (engine pid $ENGINE_PID, harvey ${HARVEY_PID:-skipped}) - waiting"
# Wait for the first primary to exit. Docker must be told WHICH exit it was:
#   engine rc=0  -> sender-health HOLD gate (probe failed, do not mail). We exit
#                   0 so `restart: on-failure` leaves the container stopped
#                   instead of re-sending a probe email every interval.
#   engine rc!=0 -> crash. Exit non-zero so Docker restarts us (crash recovery).
wait -n "$ENGINE_PID" ${HARVEY_PID:+"$HARVEY_PID"}
rc=$?
if [ "$rc" -eq 0 ]; then
    log "a primary process stopped cleanly (sender-health HOLD gate) - not restarting"
    exit 0
fi
log "a primary process exited with rc=$rc - exiting non-zero so Docker restarts"
exit 1
