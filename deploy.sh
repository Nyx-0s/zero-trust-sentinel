#!/usr/bin/env bash
# =============================================================================
# Zero-Trust Sentinel - One-Click Deployment
#
#   ./deploy.sh
#
#   1. Creates .env from interactive prompts (skipped if .env exists)
#   2. Proves the pipeline works:   python3 test_autopilot.py
#   3. Builds the image:            docker build -t zero-trust-sentinel .
#   4. Starts the stack:            docker compose up -d
#   5. Starts the 24/7 supervisor (also installs an @reboot crontab entry)
#   6. Waits for GET /health to return 200
#
# Zero manual work after the initial .env setup.
# =============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32mOK \033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mWARN\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Environment preflight ----------------------------------------------
# Fails HERE, loudly, instead of half-deploying: missing python, dead Docker
# daemon, or an incomplete build context are caught before anything runs.
info "Preflight: checking OS, python3, Docker, and the build context"

OS_NAME=$(uname -s)
ARCH=$(uname -m)
case "$OS_NAME" in
    Linux|Darwin) ok "OS: $OS_NAME ($ARCH)" ;;
    *) die "unsupported OS: $OS_NAME - deploy tested on Linux and macOS" ;;
esac
if [ "$OS_NAME" = "Linux" ] && [ "$(id -u)" -ne 0 ] && ! groups 2>/dev/null | grep -q docker; then
    warn "current user is not in the docker group - docker commands may need sudo"
fi
printf '   target arch: %s (image builds natively; cross-build with buildx)\n' "$ARCH"

command -v python3 >/dev/null 2>&1 || die "python3 not found - install Python 3.9+ (the API container itself runs Python 3.10)"
PY_VER=$(python3 -c 'import platform; print(platform.python_version())')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "python3 is $PY_VER - need 3.9+ to run the simulation and companion processes"

command -v docker >/dev/null 2>&1 || die "docker not found - install Docker Engine (docs.docker.com/engine/install/)"
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable - start it (or fix sudo/permissions), then re-run ./deploy.sh"
docker compose version >/dev/null 2>&1 || die "docker compose v2 not found - install the compose plugin"
docker compose config -q || die "docker-compose.yml does not validate - fix it before deploying"

[ -f static/index.html ] || die "static/index.html missing - the cockpit is part of the Docker build context"
[ -f requirements.txt ] || die "requirements.txt missing - incomplete checkout"
ok "preflight passed: python $PY_VER, docker ready, compose config valid"

# --- 1. .env ----------------------------------------------------------------
prompt_secret() {
    local var="$1" label="$2"
    local current
    if grep -qE "^${var}=" .env 2>/dev/null; then
        current=$(grep -E "^${var}=" .env | head -1 | cut -d= -f2-)
        printf '%s=%s\n' "$var" "$current"
        return
    fi
    local value=""
    while [ -z "$value" ]; do
        read -r -s -p "$label: " value || die "stdin closed while reading $var"
        echo >&2
        [ -n "$value" ] || echo "  (required - cannot be empty)" >&2
    done
    # Single-quote the value: DATABASE_URL-style values can contain '&' or '?',
    # which would otherwise break `set -a; . ./.env` later.
    value=${value//\'/\'\\\'\'}
    printf "%s='%s'\n" "$var" "$value"
}

# Optional variant: the key is written even when empty (Stripe keys are
# genuinely optional here - PayPal is the payment path).
prompt_optional() {
    local var="$1" label="$2"
    local current
    if grep -qE "^${var}=" .env 2>/dev/null; then
        current=$(grep -E "^${var}=" .env | head -1 | cut -d= -f2-)
        printf '%s=%s\n' "$var" "$current"
        return
    fi
    local value=""
    read -r -s -p "$label (blank to skip): " value || die "stdin closed while reading $var"
    echo >&2
    value=${value//\'/\'\\\'\'}
    printf "%s='%s'\n" "$var" "$value"
}

if [ -f .env ]; then
    info ".env already exists - keeping it (delete it to re-run setup)"
else
    info "Creating .env - enter your API keys (see README Step 1)"
    [ -t 0 ] || die "No .env and no interactive terminal. Copy .env.example and fill it in."
    {
        prompt_secret GROQ_API_KEY            "Groq API key (console.groq.com)"
        prompt_optional SENDGRID_API_KEY       "SendGrid API key (app.sendgrid.com/settings/api_keys) - preferred"
        prompt_optional RESEND_API_KEY         "Resend API key (resend.com/api-keys) - fallback"
        prompt_secret DATABASE_URL             "Neon Postgres URL (console.neon.tech)"
        prompt_optional STRIPE_SECRET_KEY     "Stripe secret key"
        prompt_optional STRIPE_WEBHOOK_SECRET "Stripe webhook secret"
        read -r -p "FROM_EMAIL [updates@yourdomain.com]: " from_email
        printf "FROM_EMAIL='%s'\n" "${from_email:-updates@yourdomain.com}"
        read -r -p "MAX_EMAILS_PER_DAY [20]: " max_emails
        printf "MAX_EMAILS_PER_DAY='%s'\n" "${max_emails:-20}"
        read -r -p "SITE_URL (public URL of this deployment, e.g. https://example.com): " site_url
        printf "SITE_URL='%s'\n" "$site_url"
        # PayPal (Native Subscribe Button + Subscriptions API). All four are
        # optional - leave blank to use AirTM/no provider. The Client ID is
        # PayPal's PUBLIC JS-SDK identifier; the Secret stays server-side.
        read -r -p "PAYPAL_MODE [live]: " pp_mode
        printf "PAYPAL_MODE='%s'\n" "${pp_mode:-live}"
        read -r -p "PAYPAL_CLIENT_ID (dashboard developer.paypal.com, REST app): " pp_cid
        printf 'PAYPAL_CLIENT_ID=%s\n' "$pp_cid"
        read -r -p "PAYPAL_SECRET (REST app secret): " pp_sec
        printf 'PAYPAL_SECRET=%s\n' "$pp_sec"
        read -r -p "PAYPAL_PLAN_ID (the \$49/mo plan, e.g. P-XXXX): " pp_plan
        printf 'PAYPAL_PLAN_ID=%s\n' "$pp_plan"
        read -r -p "PAYPAL_WEBHOOK_ID (webhook for /webhook/paypal; enables signature verification): " pp_wh
        printf 'PAYPAL_WEBHOOK_ID=%s\n' "$pp_wh"
    } > .env
    chmod 600 .env
    ok ".env written (chmod 600)"
fi

# Load .env so SITE_URL/PAYPAL_MODE/HARVEY knobs are visible below. Without
# this, 'harvey train' would silently skip even though SITE_URL is configured.
set -a
# shellcheck disable=SC1091
. ./.env
set +a
ok ".env loaded (SITE_URL=${SITE_URL:-unset}, PAYPAL_MODE=${PAYPAL_MODE:-live})"

# --- 2. Prove the pipeline (no live keys needed) ----------------------------
info "Running the test gate: autopilot + resilient-brain + business-intel"
python3 test_autopilot.py || die "Autopilot simulation failed - not deploying"
python3 test_resilient_brain.py || die "Resilient Brain regression failed - not deploying"
python3 test_business_intel.py || die "Business-intelligence tests failed - not deploying"
ok "test gate PASSED (autopilot 15 stages, rate-limit/retry/persistence, founder-skill integration)"

# --- 3. Build ---------------------------------------------------------------
info "Building Docker image (arm64/amd64 aware)"
docker build -t zero-trust-sentinel . || die "docker build failed"
ok "Image built: zero-trust-sentinel"

# --- 4. Start ---------------------------------------------------------------
info "Starting stack (docker compose up -d)"
docker compose up -d || die "docker compose up failed"
ok "Stack started"

# --- 5. Supervisor (self-healing + @reboot persistence) ---------------------
info "Starting 24/7 supervisor"
chmod +x supervisor.sh
if pgrep -f "bash.*supervisor\.sh" >/dev/null 2>&1; then
    ok "supervisor already running"
elif command -v tmux >/dev/null 2>&1; then
    # Managed tmux session: survives the deploying shell, inspectable via
    # 'tmux attach -t sentinel-supervisor', restarted cleanly on re-deploy.
    tmux has-session -t sentinel-supervisor 2>/dev/null && tmux kill-session -t sentinel-supervisor
    if tmux new-session -d -s sentinel-supervisor -c "$APP_DIR" './supervisor.sh'; then
        ok "supervisor started in tmux session 'sentinel-supervisor' (attach to watch: tmux attach -t sentinel-supervisor)"
    else
        nohup ./supervisor.sh >> supervisor.log 2>&1 &
        ok "supervisor started via nohup fallback (pid $!)"
    fi
else
    nohup ./supervisor.sh >> supervisor.log 2>&1 &
    ok "supervisor started via nohup (pid $!) - install tmux for a managed session"
fi

# Reboot persistence + daily win-back cron via user crontab (no sudo required)
if command -v crontab >/dev/null 2>&1; then
    if ! crontab -l 2>/dev/null | grep -q "supervisor\.sh"; then
        (crontab -l 2>/dev/null; echo "@reboot cd $APP_DIR && ./supervisor.sh >> supervisor.log 2>&1") | crontab -
        ok "installed @reboot crontab entry"
    else
        ok "@reboot crontab entry already present"
    fi
    if ! crontab -l 2>/dev/null | grep -q "win_back_cron\.py"; then
        (crontab -l 2>/dev/null; echo "0 10 * * * cd $APP_DIR && set -a && . ./.env 2>/dev/null && set +a && python3 win_back_cron.py >> win_back.log 2>&1") | crontab -
        ok "installed daily win_back_cron entry (10:00)"
    else
        ok "win_back_cron crontab entry already present"
    fi
fi

# --- 6. Health verification -------------------------------------------------
info "Waiting for GET /health to return 200"
for i in $(seq 1 30); do
    if curl -fsS -m 5 http://localhost:${API_PORT:-8000}/health 2>/dev/null | grep -q healthy; then
        ok "API healthy after ${i} attempt(s)"
        break
    fi
    [ "$i" -eq 30 ] && die "API did not become healthy in 150s - check: docker compose logs api"
    sleep 5
done

# --- 6b. Restart survival (the HOLD gate must not turn into a restart loop) ----
if [ "${SKIP_RESTART_CHECK:-0}" = "1" ]; then
    info "restart-survival check skipped (SKIP_RESTART_CHECK=1)"
else
    info "Verifying services survive a container restart"
    docker compose restart api >/dev/null 2>&1 || die "docker compose restart api failed"
    healthy=0
    for i in $(seq 1 20); do
        if curl -fsS -m 5 http://localhost:${API_PORT:-8000}/health 2>/dev/null | grep -q healthy; then
            healthy=1; break
        fi
        sleep 3
    done
    [ "$healthy" = "1" ] || die "API unhealthy after restart - docker compose logs api"
    ok "API healthy after container restart"

    # Worker HOLD semantics: exit 0 must leave the container stopped, not looping.
    if docker inspect -f '{{.RestartCount}}' sentinel-worker >/dev/null 2>&1; then
        before=$(docker inspect -f '{{.RestartCount}}' sentinel-worker)
        ok "worker restart policy observed (RestartCount=$before, policy=on-failure)"
    fi
fi

# --- 7. Harvey (the Hunter) -------------------------------------------------
# IMPORTANT: install from GitHub. PyPI's 'harvey' is an unrelated 2015
# license-management tool (pypi.org/project/harvey). The sales agent that
# drives the Claude Code CLI lives at github.com/ethanplusai/harvey.
if [ "${SKIP_HARVEY:-0}" = "1" ]; then
    info "Harvey skipped (SKIP_HARVEY=1)"
else
    info "Harvey: installing the sales agent from GitHub"
    if ! command -v harvey >/dev/null 2>&1; then
        if [ ! -d "$APP_DIR/.harvey" ]; then
            git clone --depth 1 https://github.com/ethanplusai/harvey "$APP_DIR/.harvey" \
                >>"$APP_DIR/deploy.log" 2>&1 || warn "harvey clone failed (see deploy.log)"
        fi
        if [ -d "$APP_DIR/.harvey" ]; then
            pip3 install -e "$APP_DIR/.harvey" >>"$APP_DIR/deploy.log" 2>&1 \
                || warn "harvey pip install failed (see deploy.log)"
        fi
    fi

    if command -v harvey >/dev/null 2>&1; then
        ok "harvey CLI installed"
        if command -v claude >/dev/null 2>&1; then
            # Our tuned config/skills (harvey.yaml, skills/, harvey_discovery.md)
            # are read from this directory, so run harvey from $APP_DIR.
            if [ -n "${SITE_URL:-}" ]; then
                (cd "$APP_DIR" && harvey train "$SITE_URL" >>deploy.log 2>&1) \
                    || warn "harvey train failed (see deploy.log)"
                (cd "$APP_DIR" && harvey signals --confirm free >>deploy.log 2>&1) \
                    || warn "harvey signals failed (see deploy.log)"
                ok "harvey trained on $SITE_URL"
            else
                info "SITE_URL not set - skipping 'harvey train' (add it to .env, then run: harvey train \$SITE_URL)"
            fi

            if command -v tmux >/dev/null 2>&1; then
                tmux has-session -t harvey 2>/dev/null \
                    || tmux new-session -d -s harvey -c "$APP_DIR" 'harvey run' 2>>"$APP_DIR/deploy.log" \
                    || warn "could not start tmux harvey session"
                ok "harvey run loop in tmux session 'harvey'"
            else
                (cd "$APP_DIR" && nohup harvey run >> harvey.log 2>&1 &)
                ok "harvey run loop started via nohup (install tmux for a managed session)"
            fi
        else
            warn "Claude Code CLI ('claude') not found - install it, then run: harvey train \$SITE_URL && harvey run"
        fi
    else
        warn "Harvey unavailable - the core Sentinel stack is still live"
    fi
fi

echo
echo "============================================================"
echo " ZERO-TRUST SENTINEL IS LIVE"
echo "   API:      http://localhost:${API_PORT:-8000}/health"
echo "   Docs:     http://localhost:${API_PORT:-8000}/docs"
echo "   Logs:     docker compose logs -f api worker"
echo "   HTTPS:    docker compose --profile proxy up -d   (Caddy)"
echo "   Seeding:  python3 seed_leads.py   (social proof assets)"
echo "   Harvey:   tmux attach -t harvey   (discovery loop)"
echo ""
echo " UPGRADE:   git pull && ./deploy.sh"
echo " ROLLBACK:  git checkout <last-good-sha> && ./deploy.sh"
echo "            (data is safe: it lives in the postgres_data volume;"
echo "             DB restore: scripts/db_migration.sh restore <dump>)"
echo "============================================================"
exit 0
