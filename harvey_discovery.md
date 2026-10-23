# Harvey Discovery Playbook - Zero-Trust Sentinel

Goal: find B2B SaaS, Fintech, and E-commerce companies (10-50 employees) with
verifiable external-surface signals, profile them, and submit them to the
Sentinel capture endpoint. Discovery only touches PUBLIC data.

## The Signal Dictionary

| Signal | What counts as confirmed |
|---|---|
| `exposed_api` | A live `/docs`, `/api`, `/swagger`, or `/openapi` endpoint on their domain |
| `staging_exposed` | A `staging.`, `dev.`, `test.`, or `uat.` subdomain that resolves publicly |
| `outdated_security` | A `/security` or `/trust` page whose last update is older than 12 months |
| `running_ads` | Active Google Ads pointing at their domain (ad library or landing-page 404s count) |
| `custom_domain` | Branded production domain (confirms a real company, not a hobby project) |

## Hunt 1: The API-First Hunt (primary)

Companies with a public API buy developer-tooling security and have the most to
lose from exposure.

1. Prioritize targets that expose `/docs`, `/api`, `/swagger`, or `/openapi`.
2. Note the tech in response headers (framework, gateway, version leaks).
3. Record exactly what is public: docs URL, auth method (none? API key in query?), rate-limit headers.
4. That note becomes the `exposed_api` observation in email 1.

## Hunt 2: The Staging Hunt (highest severity)

1. Check DNS for `staging.`, `dev.`, `test.`, `uat.` on their apex.
2. A resolving staging box with a login page or seeded data = `staging_exposed`.
3. This is the strongest Trojan Horse observation - it is concrete, checkable, and rare to survive review.

## Hunt 3: The Signal Confirmation (gate before submit)

- **Harvey must confirm at least 2 signals before sending the lead to Sentinel.**
- `custom_domain` counts as one signal (identity confirmation) but never as the only signal.
- Record every confirmed signal with the exact URL or DNS record that proves it.
- Zero-signal or one-signal companies go to a "watch list", not to capture.

## The Sentinel Loop (what to do with a confirmed lead)

```bash
curl -X POST https://YOUR-DOMAIN/capture \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "stripe.com",
    "email": "",
    "name": "Discovered by Harvey",
    "signals": ["exposed_api", "staging_exposed"],
    "harvey_ref": "hv-2026-10-22-001"
  }'
```

Field contract:

- `domain` (required): apex domain, no protocol.
- `email`: the prospect's email IF you have a permission-based reason to include
  it. Leave empty for pure discovery leads - empty-email leads run the scan and
  the public report only, and the outbound engine will never mail them
  (Resend AUP: opt-in required).
- `signals` (list): only signals confirmed per the gate above.
- `harvey_ref` (string): your discovery reference, used to tie replies back to
  the finding.

What happens next (no action needed from Harvey):

1. Sentinel runs the LangGraph swarm. The Analyst prioritizes findings that
   confirm your `signals`; the Executive Summary references them (e.g. "Given
   your public API, this exposure is high-risk").
2. The public report lands at `GET /report/{domain}` - that link is what gets
   shared with the prospect.
3. If an email was provided AND the prospect opted in, the outbound engine runs
   the 3-day follow-up sequence. Replies route to Harvey's handler agent; on
   "send me the report", queue `GET /report/{domain}` and stop pitching.

## Quality Bar

- Never submit a domain you have not personally confirmed signals for.
- Never paste credential-looking strings from discovery into any request.
- Discovery traffic stays at public, human-level rates: no directory brute-force,
  no wordlist attacks, no login attempts. If a check would look like scanning
  to the target, skip it and let Sentinel's passive scan handle it later.
