#!/usr/bin/env bash
# =============================================================================
# Zero-Trust Sentinel - 24/7 Supervisor
#
# Keeps the autonomous pipeline alive across crashes and reboots:
#   1. Process watchdog - restarts outbound_engine.py if it dies
#   2. Harvey watchdog  - restarts the 'harvey run' discovery loop (tmux or
#                         nohup) if the Brain dies; skipped when harvey isn't
#                         installed or SKIP_HARVEY=1
#   3. HTTP heartbeat   - GET /health every 5 min; restarts the Docker
#                         container (and the API inside it) on failure
#   4. Log rotation     - truncates *.log files beyond MAX_LOG_BYTES
#
# Start:   nohup ./supervisor.sh >> supervisor.log 2>&1 &
# Reboot:  deploy.sh installs an @reboot crontab entry for this script.
# Tunables (env): CHECK_INTERVAL, HEARTBEAT_INTERVAL, MAX_LOG_BYTES, HEALTH_URL
# =============================================================================
set -uo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEALTH_URL="${HEALTH_URL:-http://localhost:8000/health}"
CHECK_INTERVAL="${CHECK_INTERVAL:-30}"          # seconds between watchdog checks
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-300}" # seconds between health probes
MAX_LOG_BYTES="${MAX_LOG_BYTES:-10485760}"      # 10 MB per log file
CONTAINER="${CONTAINER:-zero-trust-sentinel}"

tick=0
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [supervisor] $*"; }

# --- 1. Process watchdog ----------------------------------------------------
engine_running() {
    # Matches only a python process running outbound_engine.py from APP_DIR.
    pgrep -f "python3? ${APP_DIR}/outbound_engine\.py" >/dev/null 2>&1
}

ensure_engine() {
    if ! engine_running; then
        log "outbound_engine.py not running - starting it"
        (
            cd "$APP_DIR" || exit 1
            # shellcheck disable=SC1091
            [ -f .env ] && set -a && . ./.env && set +a
            nohup python3 outbound_engine.py >> outbound.log 2>&1 &
            log "outbound_engine.py started (pid $!)"
        )
    fi
}

# --- 1b. Harvey loop watchdog (the "Brain") --------------------------------
harvey_running() {
    # Matches the harvey worker started by deploy.sh (tmux 'harvey run' or
    # nohup 'harvey run'). The supervisor's own cmdline never contains the
    # phrase, so this cannot self-match.
    pgrep -f "harvey run" >/dev/null 2>&1
}

ensure_harvey() {
    [ "${SKIP_HARVEY:-0}" = "1" ] && return 0
    command -v harvey >/dev/null 2>&1 || return 0   # not installed -> nothing to watch
    if ! harvey_running; then
        log "harvey run loop not running - restarting it"
        (
            cd "$APP_DIR" || exit 1
            # shellcheck disable=SC1091
            [ -f .env ] && set -a && . ./.env && set +a
            if command -v tmux >/dev/null 2>&1; then
                tmux has-session -t harvey 2>/dev/null && tmux kill-session -t harvey
                if tmux new-session -d -s harvey -c "$APP_DIR" 'harvey run'; then
                    log "harvey run restarted in tmux session 'harvey'"
                else
                    log "could not start harvey tmux session"
                fi
            else
                nohup harvey run >> harvey.log 2>&1 &
                log "harvey run restarted (pid $!)"
            fi
        )
    fi
}

# --- 2. HTTP heartbeat ------------------------------------------------------
heartbeat() {
    if ! curl -fsS -m 10 "$HEALTH_URL" >/dev/null 2>&1; then
        log "HEARTBEAT FAILED ($HEALTH_URL) - restarting container $CONTAINER"
        if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
            docker restart "$CONTAINER" >> supervisor.log 2>&1 || log "docker restart failed"
        else
            log "container $CONTAINER not running - docker compose up -d"
            (cd "$APP_DIR" && docker compose up -d) >> supervisor.log 2>&1 || log "compose up failed"
        fi
        sleep 10
        curl -fsS -m 10 "$HEALTH_URL" >/dev/null 2>&1 \
            && log "heartbeat recovered after restart" \
            || log "HEARTBEAT STILL FAILING after restart"
    fi
}

# --- 3. Log rotation --------------------------------------------------------
rotate_logs() {
    local f size
    for f in "$APP_DIR"/*.log; do
        [ -f "$f" ] || continue
        size=$(wc -c <"$f" | tr -d ' ')
        if [ "$size" -gt "$MAX_LOG_BYTES" ]; then
            tail -n 500 "$f" >"${f}.tmp" && mv "${f}.tmp" "$f"
            log "rotated $(basename "$f") (was ${size} bytes)"
        fi
    done
}

# --- Main loop --------------------------------------------------------------
log "supervisor started (pid $$) - check=${CHECK_INTERVAL}s heartbeat=${HEARTBEAT_INTERVAL}s"
ensure_engine
ensure_harvey

while true; do
    ensure_engine
    ensure_harvey

    tick=$((tick + CHECK_INTERVAL))
    if [ "$tick" -ge "$HEARTBEAT_INTERVAL" ]; then
        heartbeat
        tick=0
    fi

    # Rotate logs once every ~10 checks to avoid stat calls every loop
    if [ $(( (RANDOM % 10) + 1 )) -eq 1 ]; then
        rotate_logs
    fi

    sleep "$CHECK_INTERVAL"
done
