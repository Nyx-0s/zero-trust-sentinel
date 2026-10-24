# GO-LIVE — Zero-Trust Sentinel (Distributed: Replit Body · Laptop Brain · SendGrid Voice)

**Face:** `https://zerodaysentinel.xo.je`
**Body:** `https://zero-trust-sentinel--onthecontraryan.replit.app`
**Voice:** SendGrid, domain `zerodaysentinel.xo.je` (Resend is the coded fallback)
**Brain:** `python3 hunter.py` on the laptop
**Wallet:** PayPal Native Button, plan `$49/mo`

Nothing on this page is optional. If one row is missing, the Autopilot is not
autonomous — it is a demo with a broken limb.

---

## 1. DNS records for `zerodaysentinel.xo.je`

Managed at your DNS provider (the `xo.je` zone). Exact records:

| Type | Name | Value / Target | Purpose |
|---|---|---|---|
| `CNAME` | `@` | `zero-trust-sentinel--onthecontraryan.replit.app` | The Face → the Body |
| `CNAME` | `www` | `zero-trust-sentinel--onthecontraryan.replit.app` | apex alias, same target |
| `CNAME` | `em3457` | `u117291738.wl239.sendgrid.net` | SendGrid link/return host |
| `CNAME` | `s1._domainkey` | `s1.domainkey.u117291738.wl239.sendgrid.net` | DKIM signing key 1 |
| `CNAME` | `s2._domainkey` | `s2.domainkey.u117291738.wl239.sendgrid.net` | DKIM signing key 2 |
| `TXT` | `_dmarc` | `v=DMARC1; p=none;` | DMARC policy — **not yet in the zone**, see below |

Notes that bite people:

- The `@` CNAME is an **apex CNAME**. Some DNS hosts (Cloudflare, Route 53
  with alias records) allow it; plain BIND and a few others reject it. If yours
  does, use an **ALIAS/ANAME/flatten** record, or an `A` record if Replit
  publishes one.
- Replit serves the custom domain over **HTTPS automatically** and provisions
  the certificate — after DNS resolves, give it 5–15 minutes, then confirm the
  padlock on `https://zerodaysentinel.xo.je` before telling anyone the site is up.
- Keep `p=none` on `_dmarc` until you have watched a week of SendGrid's
  dashboard for bounces. Only tighten to `p=quarantine`/`p=reject` after that.
- **InfinityFree free-plan limits:** the zone editor only creates CNAME, MX and
  apex SPF/TXT records — it cannot create the `_dmarc` TXT or an SPF include.
  SendGrid's auth is CNAME-only, which is exactly why it was chosen over
  Resend (whose TXT DKIM could never be published here). Domain
  authentication validates with all 3 CNAMEs even without DMARC.
- `FROM_EMAIL` must be `security@zerodaysentinel.xo.je`
  (the code defaults to exactly that) — SendGrid's domain auth covers every
  address on the domain.

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

## 2. Replit Secrets (exact list)

Set these in Replit → **Secrets** (never in code, never in `.replit`):

| Secret | Feeds | Notes |
|---|---|---|
| `GROQ_API_KEY` | `hunter.py` (laptop: env or `.env`) and any LLM scoring | Hunter reads it from `.env` on the laptop — it does **not** need to be in Replit unless the API uses it |
| `SENDGRID_API_KEY` | `outbound_engine.py`, `api.py` win-back | `SG.…` key, **Mail Send** scope only (key `autopilot-voice`); set 25 Oct 2026 |
| `RESEND_API_KEY` | fallback only | *not set on Replit* — code prefers SendGrid and falls back to Resend if this exists |
| `PAYPAL_CLIENT_ID` | `api.py` checkout + Native Button | Public JS-SDK id, also hardcoded in `static/index.html` |
| `PAYPAL_SECRET` | `api.py` server-to-server | **Secret.** Server only. |
| `PAYPAL_PLAN_ID` | `api.py` `/checkout` | `$49/mo` plan (`P-8E455735W3884671YNLNRSVQ`) |
| `PAYPAL_WEBHOOK_ID` | `api.py` `/webhook/paypal` signature verification | Create the webhook *after* the domain is live |
| `DATABASE_URL` | `db.py` (Neon Postgres) | `postgres://…?sslmode=require` |
| `FROM_EMAIL` | `outbound_engine.py`, `api.py` win-back | `security@zerodaysentinel.xo.je` |
| `SESSION_SECRET` | session signing | already present |
| `SITE_URL` | report links, referral links | `https://zerodaysentinel.xo.je` |

Set at runtime, not as secrets (Replit provides `PORT`):

- `PAYPAL_MODE` = `live` once the webhook and plan are live (`sandbox` while testing).
- `MAX_EMAILS_PER_DAY`, `JITTER_MIN_SECONDS`, `JITTER_MAX_SECONDS` — leave
  defaults until the domain has warmed.

Laptop `.env` needs: `GROQ_API_KEY`, `HUNTER_API_URL` (optional override; the
default in `hunter.py` is now `https://zerodaysentinel.xo.je`).

---

## 3. PayPal wiring

1. App + credentials → REST app → copy the **Client ID** (goes in Secrets *and*
   is already hardcoded in `static/index.html`).
2. Subscriptions → plan `$49/mo` → copy the **plan id** (already hardcoded).
3. Webhooks → add `https://zerodaysentinel.xo.je/webhook/paypal` with events:
   `PAYPAL.BILLING.SUBSCRIPTION.ACTIVATED`, `.CANCELLED`, `.PAYMENT.FAILED`.
   Copy the **Webhook ID** into `PAYPAL_WEBHOOK_ID`.
4. Flip `PAYPAL_MODE` to `live` only after step 3 succeeds.

---

## 4. Run order (the Autopilot boot sequence)

1. **DNS** above resolves; `https://zerodaysentinel.xo.je/health` returns
   `{"status":"healthy"}` — not Replit's 307 auth shield.
2. **Replit → Run** (starts `uvicorn api:app`). Cockpit at `/`.
3. **Replit → Shell →** `python outbound_engine.py` — read the first two lines:
   - `[HEALTHCHECK] GO: SendGrid accepted the test email …` → the Voice is live.
   - `[HEALTHCHECK] HOLD: …` → **stop.** Fix domain auth/DKIM/API key before the
     engine mails a single real lead.
4. **Laptop →** `python3 hunter.py --dry-run` (see what the Brain *would* send),
   then `python3 hunter.py` (real ingest). Every lead prints
   `✅ [HUNT] <domain> ingested.` or `❌ [HUNT] <domain> failed: …`.
5. **Laptop →** `python3 verify_live.py` — prints **GO-LIVE** or **HOLD**.

---

## 5. What "HOLD" means, precisely

`verify_live.py` prints `HOLD` if any of these are true, and names the limb:

- `/health` unreachable, non-200, or behind Replit's `307 __replshield` → the
  Body is private; set the deployment to public.
- `/capture` does not return `200` with a `scan_id` → the Brain cannot ingest.
- `/task/{id}` never reaches `completed` → the pipeline is stalled.
- `id="digital-twin"` missing from `/` → subscribers lose the flagship feature.

A HOLD is not a warning. It means the Autopilot is currently manual.

---

## 6. Observed state — 25 Oct 2026 (measured, not assumed)

| Limb | Target | Result |
|---|---|---|
| Body | `https://zero-trust-sentinel--onthecontraryan.replit.app` | **GO-LIVE** — `/health` 200 `healthy`; `POST /capture` → `200 started scan_id=1`; `/task/1` → `hot`; cockpit serves the Digital Twin card with `--` placeholders |
| Face | `https://zerodaysentinel.xo.je` | **HOLD** — apex/www still resolve to `185.27.134.65` (`A` record), which presents the shared **`CN=xo.je` (ZeroSSL)** certificate and serves a JS challenge (`/aes.js`), not the Replit app. |
| Voice | SendGrid | **DNS GO / end-to-end pending** — all 3 CNAMEs resolve from the authoritative NS and SendGrid reports the domain **Verified**; `SENDGRID_API_KEY` (Mail Send only) is stored in Replit Secrets. The startup `[HEALTHCHECK]` probe has **not yet been run on Replit** — run step 3 above and require `GO` before the engine mails a real lead. `_dmarc` absent (InfinityFree free plan cannot create it; advisory only). |

Fixes, in order:

1. Change `@` and `www` from the current `A 185.27.134.65` to
   `CNAME → zero-trust-sentinel--onthecontraryan.replit.app` (or ALIAS/flatten).
   Then in Replit → Deployments → Custom Domain, add `zerodaysentinel.xo.je`
   so Replit provisions the certificate for *that* name — not the shared `xo.je` one.
2. ~~Add the four Resend records~~ **superseded**: the Voice moved to SendGrid
   (Resend's TXT DKIM is unpublishable on the InfinityFree free plan). The
   three SendGrid CNAMEs are live and verified. Remaining: run the startup
   health check on Replit and confirm `[HEALTHCHECK] GO`.
3. Re-run `python3 verify_live.py` — it must print **GO-LIVE** for
   `zerodaysentinel.xo.je`, not just for the Replit URL.

Test artifacts left behind by these probes: lead `scan_id=1` for `example.com`
in Neon (from `verify_live.py`) — safe to delete.

