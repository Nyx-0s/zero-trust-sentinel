# GO-LIVE — Zero-Trust Sentinel (Distributed: Vercel Body · GitHub Actions Brain · SendGrid Voice)

**Face:** `https://zerodaysentinel.xo.je` (InfinityFree static hosting)
**Body:** `https://zero-trust-sentinel-opal.vercel.app` (Vercel Hobby, Python runtime)
**Voice:** SendGrid, domain `zerodaysentinel.xo.je` (Resend is the coded fallback)
**Brain:** `python3 hunter.py` on the laptop, plus the `hunter-discovery` GitHub Actions loop
**Wallet:** PayPal Native Button, plan `$49/mo`

Nothing on this page is optional. If one row is missing, the Autopilot is not
autonomous — it is a demo with a broken limb.

---

## 1. DNS records for `zerodaysentinel.xo.je`

Managed at your DNS provider (the `xo.je` zone). Exact records:

| Type | Name | Value / Target | Purpose |
|---|---|---|---|
| `A` | `@` | `185.27.134.65` | The Face (InfinityFree) |
| `A` | `www` | `185.27.134.65` | apex alias, same target |
| `CNAME` | `em3457` | `u117291738.wl239.sendgrid.net` | SendGrid link/return host |
| `CNAME` | `s1._domainkey` | `s1.domainkey.u117291738.wl239.sendgrid.net` | DKIM signing key 1 |
| `CNAME` | `s2._domainkey` | `s2.domainkey.u117291738.wl239.sendgrid.net` | DKIM signing key 2 |
| `TXT` | `_dmarc` | `v=DMARC1; p=none;` | DMARC policy — **not yet in the zone**, see below |

Notes that bite people:

- The Body is **not** on this domain. `zerodaysentinel.xo.je` serves the static
  Face only; every API call from the page targets
  `DEFAULT_API = https://zero-trust-sentinel-opal.vercel.app` in
  `static/index.html` (override per-visit with `?api=<url>`).
- InfinityFree presents the challenge script (`/aes.js`) on a **cold** first
  request. Browsers clear it in one reload; `curl` without a browser
  User-Agent usually gets an empty reply. That is the host, not the site.
- Keep `p=none` on `_dmarc` until you have watched a week of SendGrid's
  dashboard for bounces. Only tighten to `p=quarantine`/`p=reject` after that.
- **InfinityFree free-plan limits:** the zone editor only creates CNAME, MX and
  apex SPF/TXT records — it cannot create the `_dmarc` TXT or an SPF include.
  SendGrid's auth is CNAME-only, which is exactly why it was chosen over
  Resend (whose TXT DKIM could never be published here). Domain
  authentication validates with all 3 CNAMEs even without DMARC.
- `FROM_EMAIL` is `updates@zerodaysentinel.xo.je` — SendGrid's domain auth
  covers every address on the domain.

### SendGrid domain authentication (verified)

Pulled live from the authoritative nameserver on 25 Oct 2026 — all three
CNAMEs resolve, and SendGrid → Settings → Sender Authentication reports the
domain **Verified**:

```
em3457.zerodaysentinel.xo.je        CNAME  u117291738.wl239.sendgrid.net.
s1._domainkey.zerodaysentinel.xo.je CNAME  s1.domainkey.u117291738.wl239.sendgrid.net.
s2._domainkey.zerodaysentinel.xo.je CNAME  s2.domainkey.u117291738.wl239.sendgrid.net.
```

SendGrid's wizard still shows a DMARC *warning* (advisory only — domain auth
reports `"valid": true` without it). If `_dmarc` is ever added, start with
`v=DMARC1; p=none;`.

If SendGrid ever rotates these keys the new values replace these — an outdated
DKIM record silently breaks every email the Voice sends.

---

## 2. Vercel environment variables (exact list)

Set with `vercel env add <NAME> production` (values from `.env`; never commit
them, never paste them in chat). All 16 are present on both `preview` and
`production` as of 28 Oct 2026:

| Variable | Feeds | Notes |
|---|---|---|
| `GROQ_API_KEY` | `main.py` LangGraph analysis, `hunter.py` | required at import time — without it `/health` reports `llm_configured: false` |
| `SENDGRID_API_KEY` | `outbound_engine.py`, `api.py` win-back | `SG.…` key, **Mail Send** scope only (key `autopilot-voice`); set 25 Oct 2026 |
| `RESEND_API_KEY` | fallback only | code prefers SendGrid and falls back to Resend if this exists |
| `FROM_EMAIL` | outbound engine, win-back | `updates@zerodaysentinel.xo.je` |
| `DATABASE_URL` | `db.py` (Neon Postgres) | `postgresql://…?sslmode=require` |
| `SITE_URL` | report/unsubscribe links in email, hunter target | `https://zero-trust-sentinel-opal.vercel.app` |
| `PAYPAL_CLIENT_ID` | `api.py` checkout + Native Button | public JS-SDK id, also hardcoded in `static/index.html` |
| `PAYPAL_SECRET` | `api.py` server-to-server | **secret** |
| `PAYPAL_PLAN_ID` | `api.py` `/checkout` | `$49/mo` plan (`P-8E455735W3884671YNLNRSVQ`) |
| `PAYPAL_WEBHOOK_ID` | `/webhook/paypal` signature verification | create the webhook *after* the domain is live |
| `PAYPAL_MODE` | which PayPal host the SDK calls | `sandbox` while testing, `live` when ready |
| `MAX_EMAILS_PER_DAY` | outbound engine daily cap | `40` (Black October window; dial back to 20 after) |
| `JITTER_MIN_SECONDS` / `JITTER_MAX_SECONDS` | pacing between sends | `30` / `60` |
| `CRON_SECRET` | `/internal/run-batch` gate | random 48-hex; same value as the GitHub secret |
| `INLINE_SCAN` | `api.py` | `1` — serverless has no background task, scans run in-request |

GitHub Actions reads its own copy of `SITE_URL`, `CRON_SECRET`,
`DATABASE_URL`, `GROQ_API_KEY`, `SENDGRID_API_KEY`, `RESEND_API_KEY`,
`FROM_EMAIL`, `MAX_EMAILS_PER_DAY`, `JITTER_*` as repository secrets
(`gh secret set <NAME> --repo Nyx-0s/zero-trust-sentinel`).

---

## 3. PayPal wiring

1. App + credentials → REST app → copy the **Client ID** (goes in Vercel env
   *and* is already hardcoded in `static/index.html`).
2. Subscriptions → plan `$49/mo` → copy the **plan id** (already hardcoded).
3. Webhooks → add `https://zero-trust-sentinel-opal.vercel.app/webhook/paypal`
   with events: `PAYPAL.BILLING.SUBSCRIPTION.ACTIVATED`, `.CANCELLED`,
   `.PAYMENT.FAILED`. Copy the **Webhook ID** into `PAYPAL_WEBHOOK_ID`.
   (The Face is static and cannot receive webhooks — the Body must own them.)
4. Flip `PAYPAL_MODE` to `live` only after step 3 succeeds.

---

## 4. Run order (the Autopilot boot sequence)

1. `vercel deploy --prod` → `GET https://zero-trust-sentinel-opal.vercel.app/health`
   returns `{"status":"healthy"}` (with `llm_configured: true` and
   `email_sender: "sendgrid"`).
2. Upload `static/` to InfinityFree `htdocs/` over FTP; the Face must serve
   `DEFAULT_API = https://zero-trust-sentinel-opal.vercel.app`.
3. **Sender-health gate:** run the probe once —
   `python3 -c "import asyncio, outbound_engine as o; print(asyncio.run(o.OutboundEngine().resend_health_check()))"`
   - prints `True` + `[HEALTHCHECK] GO: SendGrid accepted the test email …` →
     the Voice is live.
   - `False` / `HOLD` → **stop.** Fix domain auth/DKIM/API key before the
     engine mails a single real lead.
4. **Brain:** `python3 hunter.py --dry-run` (see what it *would* send), then
   `python3 hunter.py` (real ingest), or trigger the `hunter-discovery`
   workflow (`gh workflow run hunter-discovery`).
5. **Voice:** `gh workflow run outbound-engine` (or wait for the hourly
   schedule) — it POSTs `/internal/run-batch` with `CRON_SECRET`.
6. `python3 verify_live.py` — prints **GO-LIVE** or **HOLD**.

---

## 5. What "HOLD" means, precisely

`verify_live.py` prints `HOLD` if any of these are true, and names the limb:

- `/health` unreachable, non-200, or behind an auth shield → the Body is
  private; fix the deployment's visibility.
- `/capture` does not return `200` with a `scan_id` → the Brain cannot ingest.
- `/task/{id}` never reaches `completed` → the pipeline is stalled.
- `id="digital-twin"` missing from `/` → subscribers lose the flagship feature.

A HOLD is not a warning. It means the Autopilot is currently manual.

---

## 6. Observed state — 28 Oct 2026 (measured, not assumed)

| Limb | Target | Result |
|---|---|---|
| Body | `https://zero-trust-sentinel-opal.vercel.app` | **GO-LIVE** — `/health` 200 `healthy` (`llm_configured: true`, `email_sender: sendgrid`); cockpit + all static pages 200; `POST /capture` → `started`; inline scan → `hot` with a fresh report; `/report/{domain}` refreshes past 24h; `/internal/run-batch` answers 403 without the token and 200 with it; `/api/ops/summary` returns live DB aggregates |
| Face | `https://zerodaysentinel.xo.je` | **GO** — all 19 files from `static/` uploaded to `htdocs/`; browser run of the free assessment did OPTIONS 200 → POST `/capture` 200 → `/task/7` → `/report/example.net` → score 65/100 with findings rendered. (curl without a browser UA gets the InfinityFree challenge or an empty reply — expected.) |
| Voice | SendGrid | **DNS GO / end-to-end pending** — all 3 CNAMEs resolve and SendGrid reports the domain **Verified**; `SENDGRID_API_KEY` is set on Vercel. The startup probe has **not yet been run** — run step 3 above and require `GO` before the engine mails a real lead. `_dmarc` absent (InfinityFree free plan cannot create it; advisory only). |
| Brain | `hunter.py` / Actions | **Configured** — workflow files and repo secrets are in place; loops activate once the branch is pushed |
| Wallet | PayPal | **HOLD** — webhook still points at the sandbox/old URL until step 3 is redone against the Vercel Body |

Test artifacts left behind by these probes: leads `figma.com`, `example.com`,
`example.org`, `example.net` and their reports in Neon — safe to delete before
a real launch.
