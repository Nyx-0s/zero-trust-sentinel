# Zero-Trust Sentinel - Production image
# Runs anywhere Docker does: Render.com (web + worker via dockerCommand),
# Oracle Cloud Ampere A1 (arm64), and standard amd64 hosts / docker-compose.
FROM python:3.10-slim

# TARGETARCH is injected by BuildKit (amd64 / arm64); fall back to dpkg for legacy builders.
ARG TARGETARCH
ARG GO_VERSION=1.22.5

WORKDIR /app

# System dependencies: git (testssl.sh + harvey), curl (Go download),
# openssl/bash (testssl.sh), nodejs/npm (Claude Code CLI, which Harvey drives)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openssl \
        bash \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required by the ProjectDiscovery security tools)
RUN arch="${TARGETARCH:-$(dpkg --print-architecture)}" \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install the security toolchain used by scanners.py:
#   subfinder  - subdomain enumeration
#   httpx      - live host probing
#   nuclei     - vulnerability scanning (templates pre-fetched at build time)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates -silent

# Install testssl.sh (invoked as `testssl.sh` by scanners.py)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Harvey (the sales/discovery agent) + Claude Code CLI (the brain it drives).
# Both are non-fatal: without ANTHROPIC_API_KEY the worker skips Harvey and
# runs the outbound engine alone (worker.sh degrades gracefully).
RUN git clone --depth 1 https://github.com/ethanplusai/harvey /opt/harvey \
    && pip install --no-cache-dir -e /opt/harvey \
    || echo "WARN: harvey install failed - worker will run outbound-only"
RUN npm install -g @anthropic-ai/claude-code \
    || echo "WARN: claude CLI install failed - worker will run outbound-only"

# Application code
COPY *.py ./

# Vendored founder-skill (MIT) powering /business/* - instructions + tools
COPY vendor/founder-skill ./vendor/founder-skill

# Harvey's tuned config + skills (read from the working directory)
COPY harvey.yaml harvey_discovery.md ./
COPY skills/ ./skills/

# Worker entrypoint (Render Background Worker: outbound engine + harvey +
# the daily win-back pass - Render has no user crontab)
COPY worker.sh ./worker.sh
RUN chmod +x worker.sh

# Migration + verification helpers (documented in docs/ZERO_COST_RUNBOOK.md)
COPY scripts/ ./scripts/
RUN chmod +x scripts/*.sh 2>/dev/null || true

# The "Cockpit": self-contained landing page served by the API at /
COPY static/ ./static/

# PDF report storage (mounted as ./reports:/reports by docker-compose)
RUN mkdir -p /reports
VOLUME ["/reports"]

EXPOSE 8000

# Web role (default). Render sets $PORT (default 10000) for Docker web
# services, so the container must listen there; bare-metal/compose keeps 8000.
# The Background Worker overrides this command with `bash worker.sh`.
CMD ["sh", "-c", "exec uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
