# Zero-Trust Sentinel

Autonomous external attack-surface monitoring for B2B SaaS. A LangGraph agent swarm (Scout → Analyst → Fixer → Editor → Critic) scans a domain, translates findings into business risk, and delivers a fix-it plan — powered by a permission-based inbound funnel with a referral loop.

**Stack (Free Tier):** Oracle Cloud Ampere A1 · Neon Postgres · Resend · Groq · Stripe

---

## Project Structure

```
zero-trust-sentinel/
├── api.py               # FastAPI app - 13 endpoints (capture, task, report, refer, checkout, PayPal + Stripe webhooks...)
├── main.py              # LangGraph swarm: Scout, Analyst, Fixer, Editor, Critic
├── scanners.py          # Real toolchain: subfinder, httpx, nuclei, testssl.sh
├── db.py                # Neon Postgres layer (9 tables incl. referrals, lead_stages, scan_tasks)
├── outbound_engine.py   # Permission-based follow-up sequence engine (initial → day 3 → day 7)
├── win_back_cron.py     # 30-day lifecycle win-back cron
├── prompts.py           # Agent personas + marketing copy (v0.dev landing page prompt)
├── utils.py             # Guardrails: robust_json_parse, sanitize_domain, trim_scan_for_llm
├── static/
│   └── index.html       # The "Cockpit": self-contained landing page (scan + Native PayPal Button)
├── harvey.yaml          # Harvey persona/ICP/offer (ethanplusai/harvey schema)
├── harvey_discovery.md  # Harvey hunt playbook: signals, 2-signal gate, /capture contract
├── skills/              # Harvey skills: email_frameworks, objection_handling (incl. closer replies)
├── requirements.txt     # Python dependencies
├── Dockerfile           # Production image (Go toolchain + security tools + cockpit page)
├── docker-compose.yml   # One-click deployment (Neon, reports volume, PayPal env passthrough)
├── deploy.sh            # One-click: .env -> simulation -> build -> up -> supervisor -> Harvey
├── supervisor.sh        # 24/7 watchdog: engine + Harvey loop, health heartbeat, log rotation
├── test_autopilot.py    # End-to-end simulation (mock DB/LLM/scanners/Resend/Stripe/PayPal)
├── seed_leads.py        # Generates public reports -> marketing/social_proof.json
└── marketing/
    ├── linkedin_hook.txt   # Ready-to-post LinkedIn hook for first inbound leads
    └── seed_leads.csv      # 10 high-value B2B SaaS domains for public reports
```

> **Prove it first (no API keys needed):** `python3 test_autopilot.py` runs the entire
> pipeline — capture → scan → LLM → report → outbound email → Stripe payment →
> cancellation → 30-day win-back → Native PayPal activation → cockpit page —
> against an in-memory database and prints a 14-stage PASS/FAIL report.

---

## Step 1: The 5-Minute Setup

Create a `.env` file in the project root:

```bash
# LLM (free tier) - https://console.groq.com/keys
GROQ_API_KEY=gsk_...

# Email (free tier, permission-based only) - https://resend.com/api-keys
RESEND_API_KEY=re_...
FROM_EMAIL=updates@yourdomain.com
MAX_EMAILS_PER_DAY=20

# Database (free tier) - https://console.neon.tech (use the pooled connection string)
DATABASE_URL=postgresql://user:password@ep-xxx.aws.neon.tech/neondb?sslmode=require

# Payments - India-based merchant (global-ready)
# 1. PayPal (primary): developer.paypal.com -> REST app -> Client ID + Secret;
#    create a $49/mo Plan (Subscriptions) and a webhook for /webhook/paypal.
PAYPAL_CLIENT_ID=...
PAYPAL_SECRET=...
PAYPAL_PLAN_ID=...
PAYPAL_WEBHOOK_ID=...
# 2. AirTM (fallback): hosted payment link for manual recurring billing
# AIRTM_PAYMENT_LINK=https://...
# Public URL of this deployment (success/cancel URLs + 'harvey train')
SITE_URL=https://yourdomain.com

# Stripe - still used by /checkout/tripwire (72-hour free trial offer) and
# /webhook/stripe. Leave unset if Stripe is unavailable to you.
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### PayPal mode (sandbox vs live)

`PAYPAL_MODE` selects the REST host: `sandbox` -> `api-m.sandbox.paypal.com`,
`live` (default) -> `api-m.paypal.com`. Sandbox credentials sent to the live
host fail with `401 invalid_client`, so set `PAYPAL_MODE=sandbox` while testing.
`PAYPAL_API_BASE` overrides the host explicitly if you ever need it.

### Getting your keys

| Service | Where | Free tier |
|---|---|---|
| **Groq** | console.groq.com → API Keys | Yes, generous LLM limits |
| **Resend** | resend.com → API Keys | 3,000 emails/month, 100/day |
| **Neon** | console.neon.tech → Connection Details | Yes, serverless Postgres |
| **PayPal** | developer.paypal.com → My Apps & Credentials (REST app) | No monthly fee; per-transaction on cross-border USD |
| **Stripe** | dashboard.stripe.com → Developers → API keys | Test mode, no fees until live |

### Resend subdomain setup (do this before sending)

1. In Resend: **Domains → Add Domain** → enter `updates.yourdomain.com`.
2. Copy the **exact** SPF, DKIM, and DMARC DNS records Resend gives you into your DNS provider.
3. Start DMARC permissive: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`.
4. Wait for verification (usually <48h), then set `FROM_EMAIL=updates@yourdomain.com`.
5. Warm-up: send your first 5–10 emails to your own inbox before any outreach.

---

## Step 2: The Deployment

**One-Click (recommended):**

```bash
./deploy.sh
```

This prompts for your keys (writes `.env`, chmod 600), runs the 14-stage
Autopilot simulation as a pre-deploy gate, builds the image, starts the stack,
starts the 24/7 supervisor, installs an `@reboot` crontab entry, and waits for
`GET /health` to return 200. Re-running is idempotent (keeps `.env`).

**Manual equivalent:**

```bash
docker build -t zero-trust-sentinel .
docker compose up -d --build
```

Verify:

```bash
curl http://localhost:8000/health
# {"status":"healthy","service":"zero-trust-sentinel"}
```

Schema is created automatically on first boot (`init_db` runs at startup — all 9 tables + the `trajectories` table).

---

## Deploy on Render.com (managed, no VPS)

The same image runs as **two services** on Render plus a managed Postgres —
all declared in [`render.yaml`](render.yaml) as a Blueprint:

| Service | Type | Command | What it runs |
|---|---|---|---|
| `sentinel-web` | Web Service | image CMD (`uvicorn api:app`, `$PORT`-aware) | API + Digital Twin `/simulate` + the static cockpit at `/` |
| `sentinel-worker` | Background Worker | `bash worker.sh` | `outbound_engine.py` (Voice), `harvey run` (Brain), daily win-back pass |
| `sentinel-db` | Postgres (Starter, $7/mo) | — | clients, reports, trajectories, subscriptions, events |

**Steps:**

1. Push this repo to GitHub.
2. Render dashboard → **New → Blueprint** → select the repo. Render reads
   `render.yaml` and creates all three resources; `DATABASE_URL` is wired
   automatically from `sentinel-db` (SSL is added by `db.py` when the host is
   not localhost).
3. Open each service's **Environment** tab and fill the `sync: false` secrets
   (GROQ, RESEND, ANTHROPIC for Harvey, PayPal, `SITE_URL` = the web service's
   public URL). Nothing secret lives in git.
4. Deploy. The first Docker build is heavy (Go toolchain + nuclei templates) —
   expect a long initial build. `init_db` creates the schema on first boot.
5. Point the PayPal webhook at `https://<your-web-service>/webhook/paypal` and
   set `SITE_URL` before training Harvey.

**Plan notes (real numbers):** Render's Free Postgres **expires 30 days after
creation**, so the Blueprint defaults to Starter ($7/mo). Free web/worker plans
sleep after inactivity — bad for PayPal webhooks and a 24/7 pipeline — hence
Starter there too. To run outbound-only (no Harvey), set `SKIP_HARVEY=1` on the
worker; the worker also skips Harvey automatically when `ANTHROPIC_API_KEY` or
the `claude` CLI is missing.

Prefer the VPS path? `./deploy.sh` + `supervisor.sh` still do the same job on
any Docker host (see Step 2 and Step 4).

---

## Step 3: The "First 10 Leads" Protocol

This is a **content-marketing** loop, not cold outreach: public reports only, no emails without opt-in.

1. **Generate public reports** for the seed list in `marketing/seed_leads.csv`:

   ```bash
   while IFS=, read -r domain industry score; do
     [ "$domain" = "domain" ] && continue
     echo "Requesting public report for $domain..."
     curl -s "http://localhost:8000/report/$domain"
     echo
     sleep 2
   done < marketing/seed_leads.csv
   ```

   Each call triggers a scan; poll `GET /task/{task_id}` until `"status": "completed"`. The results live at `GET /report/{domain}` — these URLs are your shareable content.

2. **Post the LinkedIn hook**: copy `marketing/linkedin_hook.txt` (replace `[YourDomain]`), post it, and link a public report as proof.

3. **Capture inbound**: every visitor who requests their own scan hits `POST /capture` — that opt-in is what the follow-up engine mails to (Resend AUP compliant).

---

## Step 4: The "Auto-Mode" Activation (Self-Healing)

`deploy.sh` starts the supervisor for you (in a tmux session named
`sentinel-supervisor` when tmux is available). To start it manually:

```bash
# managed session (watch logs live: tmux attach -t sentinel-supervisor)
tmux new -d -s sentinel-supervisor -c "$PWD" './supervisor.sh'
# or plain background process
nohup ./supervisor.sh >> supervisor.log 2>&1 &
```

The supervisor keeps the system alive 24/7:
- **Process watchdog** — restarts `outbound_engine.py` if it dies (permission-based,
  20 emails/day cap, circuit breaker at 3 failures).
- **Harvey watchdog** — restarts the `harvey run` discovery loop (tmux-aware);
  skipped when harvey isn't installed or `SKIP_HARVEY=1`.
- **HTTP heartbeat** — `GET /health` every 5 minutes; restarts the Docker container
  on failure.
- **Log rotation** — truncates `*.log` files at 10 MB so the disk never fills.
- **Reboot survival** — `deploy.sh` installs an `@reboot` crontab entry.

Schedule the 30-day win-back cron (daily at 10:00):

```bash
crontab -e
# Add:
0 10 * * * cd /path/to/zero-trust-sentinel && /usr/bin/python3 win_back_cron.py >> win_back.log 2>&1
```

Both processes need the same environment as the API (`.env` loaded via `set -a; . ./.env; set +a` before running manually, or run them inside the container).

---

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/scan` | Background scan for a domain (poll `/task`) |
| GET | `/task/{task_id}` | Poll scan progress (numeric lead id or UUID) |
| POST | `/capture` | Lead magnet opt-in (+ `signals`, `harvey_ref`, `ref`); returns `client_id` for the Native Button |
| GET | `/report/{domain}` | Public security posture report (content lead magnet) |
| GET | `/report/{report_id:int}` | Download generated PDF by id |
| POST | `/refer` | Generate referral link (`referrer_id`, `referred_domain`) |
| POST | `/checkout` | Global-ready checkout (PayPal Subscriptions API, AirTM fallback) |
| POST | `/checkout/tripwire` | Tripwire: 72-hour free trial on subscription |
| POST | `/webhook/stripe` | Stripe webhooks (signature-verified, idempotent) |
| POST | `/webhook/paypal` | PayPal webhooks (signature-verified, idempotent) |
| POST | `/webhook/paypal-activate` | Native Button approval -> server-verified activation |
| GET | `/dashboard/{client_id}` | Latest risk score + top risks |
| POST | `/simulate` | **Digital Twin**: 50-round breach trajectory from the real scan (subscribers only) |
| GET | `/simulate/{client_id}` | Latest saved trajectory (subscribers only) |

---

## Global Payments (India-based merchant)

`POST /checkout` picks a provider in order:

1. **PayPal Subscriptions API** - set `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`,
   `PAYPAL_PLAN_ID`. PayPal India supports cross-border/international payments
   and documents Subscriptions + Smart Buttons for India accounts; confirm your
   account has subscriptions enabled before launch.
2. **AirTM link** - set `AIRTM_PAYMENT_LINK` to a hosted payment link
   (manual recurring; no webhooks - reconcile by hand).

`POST /webhook/paypal` verifies PayPal's transmission headers via the
`VERIFY-WEBHOOK-SIGNATURE` API (needs `PAYPAL_WEBHOOK_ID`), is idempotent, and
handles `BILLING.SUBSCRIPTION.ACTIVATED`, `PAYMENT.CAPTURE.COMPLETED`,
`BILLING.SUBSCRIPTION.CANCELLED`, `BILLING.SUBSCRIPTION.EXPIRED`, and
`BILLING.SUBSCRIPTION.PAYMENT.FAILED` (deactivation hands off to the 30-day
cron; no immediate email). `PAYPAL_SKIP_SIGNATURE_VERIFY=1` exists for local
simulation only. When going live, also subscribe to `PAYMENT.SALE.COMPLETED`
(subscription renewals) and reuse the same handler.

### Native Subscribe Button (one-click in the landing page)

The landing page (generated from `V0_DEV_PROMPT` in `prompts.py`) renders
PayPal's official Smart Subscribe Button in a modal, with the visitor's own
risk score and top 3 risks above it. Flow:

1. `POST /capture` returns `client_id` immediately -> the page stores it as
   `window.CURRENT_CLIENT_ID`.
2. The button's `createSubscription` uses your `PAYPAL_PLAN_ID` ($49/mo plan).
3. `onApprove` POSTs `{subscription_id, client_id}` to
   `POST /webhook/paypal-activate`, which **verifies the subscription
   server-to-server** with PayPal (exists, ACTIVE/APPROVED, on our plan, and
   its `custom_id` - if present - matches the client) before activating, then
   redirects to `/dashboard/{client_id}`.
4. PayPal also sends `BILLING.SUBSCRIPTION.ACTIVATED` to `/webhook/paypal`;
   both paths converge on the same subscription row (idempotent).

Because Native Button subscriptions are created in the browser, PayPal
webhooks carry only the subscription id (no `custom_id`). The activation
endpoint stores the link (`subscriptions.paypal_subscription_id`), and
`/webhook/paypal` resolves the client from it for later lifecycle events.

**PayPal Dashboard setup:** Wallet -> Webhooks -> create a webhook pointing at
`https://yourdomain.com/webhook/paypal` with events
`BILLING.SUBSCRIPTION.ACTIVATED`, `BILLING.SUBSCRIPTION.CANCELLED`,
`BILLING.SUBSCRIPTION.UPDATED`, `BILLING.SUBSCRIPTION.EXPIRED`, and
`BILLING.SUBSCRIPTION.PAYMENT.FAILED`; copy the Webhook ID into
`PAYPAL_WEBHOOK_ID`. `deploy.sh` prompts for all of these values.

Note: `/checkout/tripwire` (72-hour free trial) remains Stripe-based. If Stripe
isn't available to you, leave the Stripe keys unset and use `/checkout` only.

## Cockpit (Landing Page)

`static/index.html` is a self-contained landing page (no build step) with the
free-scan flow and the Native PayPal Subscribe Button. The API serves it at
`GET /` (registered last, so all API routes take precedence).

**Hosted with the API (default):** open `http://your-server:8000/` - the page
defaults to same-origin API calls, so nothing needs configuring.

**Hosted on Vercel/Netlify:** upload `index.html` as-is and either open it as
`https://your-frontend.vercel.app/?api=https://your-api-domain.com` or set
`API_BASE` in the file's CONFIG block to your API origin. Cross-origin calls
work because the API sends CORS headers; restrict them with
`FRONTEND_ORIGINS=https://your-frontend.vercel.app` in `.env` (default is
open, which is safe: report data is public and activation is verified
server-to-server with PayPal regardless of browser headers).

Flow: enter domain + email → `POST /capture` (returns `client_id`) → poll
`/task/{id}` until `hot`/`completed` → show score + top findings from
`/report/{domain}` → "Subscribe for $49/mo" opens the modal → PayPal approves →
`POST /webhook/paypal-activate` (server-verified) → redirect to
`/dashboard/{client_id}`.

The 24/7 supervisor watches three things now: `outbound_engine.py`, the
`harvey run` loop (tmux-aware, skipped when harvey isn't installed or
`SKIP_HARVEY=1`), and the API container via the health heartbeat.

## Harvey (Lead Discovery)

| File | Purpose |
|---|---|
| `harvey.yaml` | Persona (Senior Security Consultant), ICP (B2B SaaS/Fintech/E-commerce, 10-50), offer, compliance, warm-up - matches the real ethanplusai/harvey schema |
| `skills/email_frameworks.md` | Consultant tone + the Trojan Horse framework (every email = one verified observation) |
| `skills/objection_handling.md` | "We're already secure", "Too expensive", and the rest |
| `harvey_discovery.md` | Signal dictionary, API-first + staging hunts, 2-signal gate, `/capture` contract |

**Install from GitHub, not PyPI:** `pip install harvey` installs an unrelated
2015 license tool. The real agent (drives the Claude Code CLI) lives at
[github.com/ethanplusai/harvey](https://github.com/ethanplusai/harvey):

```bash
git clone https://github.com/ethanplusai/harvey .harvey && pip3 install -e .harvey
harvey train $SITE_URL
harvey signals --confirm free
tmux new -d -s harvey -c "$PWD" 'harvey run'
```

`./deploy.sh` performs all of these steps (skip with `SKIP_HARVEY=1`); it
requires the `claude` CLI on your subscription. The loop: Harvey confirms
**at least 2 signals** → `POST /capture` with `signals` + `harvey_ref` → the
Analyst prioritizes and the Executive Summary references them ("Given your
public API, this exposure is high-risk") → report at `GET /report/{domain}` →
replies route to Harvey's handler. Discovery leads **without an email are
scanned but never mailed** (Resend AUP: opt-in required).

## Compliance Notes (read once, sleep forever)

- **Permission-based only.** The engine mails exclusively people who opted in via `/capture`. Suppressed emails are never re-mailed. This keeps you inside Resend's AUP.
- **Rate limits:** `MAX_EMAILS_PER_DAY=20` during warm-up; raise to 50 after 72h of clean delivery (<1% bounce, <0.08% complaints). The Black October window in `.env` runs 40/day with `JITTER_MIN_SECONDS=30` - revert to 20/60 when the window closes.
- **Circuit breaker:** 3 consecutive Resend failures pauses outbound for 1 hour.
- **Scan responsibly.** Run scans against domains you own or have permission to test, and honor target sites' terms of service.
- **Stripe coupons:** win-back (20%, 3 months, single redemption) is created programmatically — use test keys until you're ready. The tripwire now uses `trial_period_days=3` (72-hour trial) instead of a 100%-off coupon.
