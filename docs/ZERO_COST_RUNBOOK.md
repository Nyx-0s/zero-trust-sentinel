# Zero-Trust Sentinel — zero-cost hosting runbook (Replit exit)

Target: **Oracle Cloud Always Free VM**, Docker Engine, local PostgreSQL,
Caddy for HTTPS, existing domain `zerodaysentinel.xo.je`. Zero recurring
infrastructure cost. Every step below is executable as written; the only
actions that need **you** are marked **[YOU]** (they require your account).

Verified 2026-10-27 against Oracle's published pages:

| Claim | Source | Status |
| --- | --- | --- |
| "Always Free services are available for an unlimited period of time" | https://www.oracle.com/cloud/free/ | published term |
| Always Free resource list (compute, block volume, objects) | https://docs.oracle.com/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm | published term |
| Always Free resources stay available "as long as you actively use your account" | Oracle free-tier pages / FAQ https://www.oracle.com/cloud/free/faq/ | published term |
| Ampere A1 allowance was reduced (4 OCPU/24 GB → 2 OCPU/12 GB, June 2026) | https://www.infoq.com/news/2026/07/oracle-cloud-free-tier-limits/ | observed change |

**Honest reading:** "Always Free" is published as unlimited-duration, *not* as
frozen allowances — Oracle reduced the Ampere A1 allowance in June 2026 with
an August 2026 compliance deadline. Budget for the possibility that the shape
you get today can be reduced again, and keep the export/rollback steps below
current. Capacity for free shapes is also not guaranteed in every region.

---

## 1. Provisioning — **[YOU]**

1. https://signup.oraclecloud.com — one Always Free account per person
   (card required for identity verification; no charge if you stay inside
   Always Free limits).
2. Choose a home region **with Ampere A1 capacity** (us-ashburn-1,
   us-phoenix-1, and ap-mumbai-1 are commonly available; if the shape shows
   "Out of capacity", try another AD/region).
3. Create the VM:
   - Shape: **VM.Standard.A1.Flex** (ARM64, start 2 OCPU / 12 GB) or
     **VM.Standard.E2.1.Micro** (AMD x86, 1/8 OCPU, 1 GB — tight but runs the
     stack; prefer A1).
   - Image: **Ubuntu 22.04 or 24.04 aarch64/amd64** matching the shape.
   - Boot volume: 47 GB (Always Free allows 200 GB total).
   - Upload your SSH public key in the wizard.
4. Open the ports in the **VCN security list** (Console → Virtual Cloud
   Network → Security Lists → Add Ingress Rules): TCP 22 (your IP only),
   TCP 80, TCP 443.

## 2. First-time server setup (paste as root/sudo)

```bash
apt-get update && apt-get install -y git curl ufw
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$SUDO_USER" 2>/dev/null || true
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp
ufw --force enable

git clone https://github.com/Nyx-0s/zero-trust-sentinel.git /opt/sentinel
cd /opt/sentinel
cp .env.example .env && chmod 600 .env
${EDITOR:-nano} .env      # fill in: GROQ_API_KEY, POSTGRES_PASSWORD, FROM_EMAIL,
                          #          PAYPAL_*, SITE_URL (no other change needed)
```

`.env` must contain the **local** database URL so the stack is self-contained:

```
DATABASE_URL=postgresql://sentinel:<POSTGRES_PASSWORD>@db:5432/sentinel
```

## 3. Deploy

```bash
cd /opt/sentinel
./deploy.sh                     # preflight → .env → test gate → build → up → health
```

What `deploy.sh` does, in order (all steps are in the script):

1. OS/arch check, python ≥ 3.9, Docker daemon, `docker compose version`,
   **`docker compose config -q`** (compose must validate before anything runs).
2. `.env` creation if missing — values are entered with hidden input and are
   never echoed back.
3. **Test gate:** `test_autopilot.py` (15 stages) + `test_resilient_brain.py`
   (rate limiter, 429 retry, failure persistence) + `test_business_intel.py`
   (founder-skill integration). A red suite stops the deploy.
4. `docker build` for the host architecture.
5. `docker compose up -d` (db + api + worker).
6. Waits for `GET /health` → 200, then **restarts the API container and waits
   for health again** (restart survival). Skip with `SKIP_RESTART_CHECK=1`.
7. Prints the upgrade and rollback commands.

Enable HTTPS (Caddy obtains and renews the certificate itself):

```bash
docker compose --profile proxy up -d
```

## 4. Worker restart semantics (the HOLD gate — do not "fix" this)

`docker-compose.yml` runs the worker with **`restart: on-failure`**:

- outbound engine exits **0** = sender-health HOLD (probe failed) → the
  container **stays stopped**. `restart: always/unless-stopped` would restart
  it on 0 and re-send probe emails every interval — the exact failure
  `replit_run.sh`'s supervisor was written to prevent.
- non-zero exit = crash → Docker restarts it (crash recovery).
- `worker.sh` already supervises the outbound engine, the harvey discovery
  loop and the daily win-back pass — never start a second copy.

Today the engine HOLDs with `Resend 403` for `zerodaysentinel.xo.je`, so
**no email is being sent**. To open sending: verify the sender domain in
Resend (DNS records in §5) or set `SENDGRID_API_KEY` (preferred — the free
zone cannot publish Resend's TXT DKIM/SPF). Then
`docker compose restart worker`.

## 5. DNS for `zerodaysentinel.xo.je`

Current state: the domain is a **static InfinityFree site (the "Face")**
whose JS points API calls at the Replit deployment (`DEFAULT_API` in
`static/index.html`). Cutover plan:

1. **[YOU]** At your DNS provider for `xo.je`, add:
   - `A  zerodaysentinel.xo.je  →  <VM public IP>`
   - `A  www                    →  <VM public IP>`
   (or `CNAME www → zerodaysentinel.xo.je`)
2. Wait for propagation (`dig +short zerodaysentinel.xo.je` returns the VM IP).
3. Start Caddy with the `proxy` profile; it provisions Let's Encrypt on the
   first request. Check: `curl -sI https://zerodaysentinel.xo.je/health`.
4. Only after HTTPS is green, retire the InfinityFree page (keep the files —
   they are `static/` in this repo, served by the API now).
5. With the API on the same origin as the page, `API_BASE` in
   `static/index.html` falls back to `window.location.origin` and the Replit
   URL becomes dead — **that is the Replit exit**; cancel/delete the Replit
   deployment once traffic is verified.

## 6. Backups (data lives in the `postgres_data` volume)

```bash
# Manual consistent backup
scripts/db_migration.sh dump backups/sentinel-$(date +%F).dump

# Nightly, keep 14 days (add with crontab -e)
0 4 * * * cd /opt/sentinel && scripts/db_migration.sh dump backups/sentinel-$(date +\%F).dump && \
  find backups -name 'sentinel-*.dump' -mtime +14 -delete
```

Off-site copy (optional, free): `rclone copy backups remote:sentinel-backups`
with any free-tier object store. Restore drill: `scripts/db_migration.sh
rollback backups/<file>.dump`.

## 7. Migration cutover (Replit/old DB → new VM DB)

```bash
# 1. dump the source (run with the OLD DATABASE_URL in .env)
scripts/db_migration.sh dump source.dump
# 2. stop writers on the old side (stop the Replit process / docker compose stop api worker)
# 3. final dump
scripts/db_migration.sh dump final.dump
# 4. on the new VM: point DATABASE_URL at the local db service, then
scripts/db_migration.sh restore final.dump     # restores + verifies
# 5. compare against the source explicitly
SOURCE_DATABASE_URL=<old-url> scripts/db_migration.sh verify final.dump
# 6. start the stack
docker compose up -d
```

`verify` prints row counts for **every** application table
(`clients, reports, lead_tasks, subscriptions, coupons, stripe_events,
lead_stages, referrals, scan_tasks, trajectories, business_projects,
business_outputs`) and lists sequences. A missing table fails the command.
Credentials are passed through the environment only — never printed, never
written to logs. Keep `source.dump` until the new deployment has run a full
day (that is the rollback).

## 8. Upgrade and rollback

```bash
# Upgrade (test gate runs first; a red suite aborts before anything restarts)
cd /opt/sentinel && ./deploy.sh

# Roll back the code
git checkout <last-good-sha> && ./deploy.sh

# Roll back the data (only if a migration went wrong)
scripts/db_migration.sh rollback backups/<pre-change>.dump
```

Database data is a Docker volume: container recreation and `docker compose
down` (without `-v`) never delete it. `docker compose down -v` **does** —
never run it on production.

## 9. Zero-cost ledger (what is free, what is metered, what can change)

| Dependency | Cost | Honest limitation |
| --- | --- | --- |
| Oracle Always Free VM | ₹0 | published as unlimited-duration; allowances already reduced once (June 2026); capacity not guaranteed in every region |
| Docker, PostgreSQL, Caddy, Let's Encrypt | ₹0 | open source, no account |
| GitHub (private repo) | ₹0 | free tier |
| Groq LLM | free tier | 7,500 TPM bucket + ~200,000 tokens/day observed cap; 429s retried with the server-stated delay |
| Resend / SendGrid | free tier | daily send limits; **currently gated** (domain authorization pending) |
| PayPal | per-transaction | no fixed fee; charges only apply when you make a sale |
| Domain `xo.je` | existing | renewal cost is yours already |
| Cloudflare (optional DNS/CDN) | ₹0 | optional; plain DNS at your registrar also works |

No paid service was added by this work. If Oracle refuses capacity, the
fallbacks each break something: **Render** free web services sleep after
15 min and its free Postgres expires in 30 days (the outbound worker cannot
live there), **Cloudflare Workers** has a 10 ms CPU limit and cannot run this
Python/LangGraph backend, **Supabase** free projects pause when idle
(database-only, not a compute replacement). The nearest working free
alternative to Oracle is any free-tier VM you already control; a paid VPS is
the first option that removes all of these caveats.

## 10. Post-deploy verification checklist

```bash
curl -fsS localhost:8000/health                 # healthy + llm_configured
curl -fsS localhost:8000/business/skills        # 11 skills
docker compose ps                               # db/api Up; worker exited(0) if HOLDed
docker inspect -f '{{.RestartCount}}' sentinel-worker   # 0 = HOLD not looping
docker compose restart api && sleep 15 && curl -fsS localhost:8000/health
docker compose logs worker --tail 50            # read the HOLD reason, if any
```

Run the suites locally before any cutover:

```bash
python3 test_autopilot.py          # 15/15 stages
python3 test_resilient_brain.py    # rate limiter + 429 retry + error persistence
python3 test_business_intel.py     # founder-skill integration
```
