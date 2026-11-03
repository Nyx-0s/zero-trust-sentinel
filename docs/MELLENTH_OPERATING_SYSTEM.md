# Mellenth Operating System — integration map

## Operating model
Mellenth is the parent brand. The operating surface is hosted by the existing Zero-Trust Sentinel FastAPI/Vercel service and Neon database. GitHub Actions runs scheduled discovery and bounded follow-up jobs. The operator dashboard is served at /mellenth and is mobile-first. No laptop process is required after deployment.

## Core pipeline
1. Discover public business prospects and record source/evidence.
2. Qualify by fit and evidence; distinguish public contact data from permission to market.
3. Prepare a tailored message; operator reviews and sends through the monitored Mellenth mailbox or an approved channel.
4. Capture replies in the mobile inbox form; classify meeting intent, interest, objection, rejection, out-of-office and opt-out.
5. Track prospect stage, deals, proposals/payment links and won revenue.
6. Suppress opt-outs immediately; never infer consent from a public email address.

## Mellenth-owned repositories and product inventory
| Repository | Role | Integration / maturity note |
|---|---|---|
| [zero-trust-sentinel](https://github.com/Nyx-0s/zero-trust-sentinel) | Security / core API | Hosts existing API, passive discovery, security assessment, database, outbound follow-up and new Mellenth operations surface. |
| [QA-AI-Employee](https://github.com/Nyx-0s/QA-AI-Employee) | Automation | Contains the ConsentArk runtime. |
| [ConsentArk](https://github.com/Nyx-0s/QA-AI-Employee/tree/main/consentark) | Permission-bounded AI employees | Product code has operator dashboard, scoped grants, audit trail and human approval gates; self-hosted deployment required. |
| [Prometheus](https://github.com/Nyx-0s/Prometheus) | Intelligence experience | Current repository is a Next.js experience/portfolio, not a verified deployed intelligence backend. |
| [rft-aqw](https://github.com/Nyx-0s/rft-aqw) | AQW | Repository is currently empty. |
| [rft-aqw-community-edition](https://github.com/Nyx-0s/rft-aqw-community-edition) | AQW Community Edition | Package scaffold only; no configured test suite. |
| [gyansetu-adse](https://github.com/Nyx-0s/gyansetu-adse) | ADSC / ADSE | Working local data preparation, validation and Playwright import workflow; customer-specific portal setup and a machine/browser runtime are required. |
| [arkhe-media-engine](https://github.com/Nyx-0s/arkhe-media-engine) | Creative automation | Current repository is a Next.js starter scaffold. |
| [Research-Setu](https://github.com/Nyx-0s/Research-Setu) | Research intelligence | Separate multi-service product; needs deployment and API contract review before runtime integration. |
| [cyberguard](https://github.com/Nyx-0s/cyberguard) | Security training | Separate product repository; not coupled to prospecting. |
| [CyberGuard-Library](https://github.com/Nyx-0s/CyberGuard-Library) | Security lab templates | Reusable lab library, not a hosted customer service. |

The operations catalog shows these products and their maturity honestly. It must not represent a scaffold or empty repository as production-ready.

## External reference repositories reviewed
These are third-party projects, not Mellenth-owned repositories. Their approaches inform workflow design; their code is not copied wholesale into the production service.

| Reference | Intended use |
|---|---|
| [First Customer Finder](https://github.com/Kappaemme-git/codex-first-customer-finder-skill) | ICP definition, customer interviews, prospect evidence and report artifacts. MIT. |
| [Google Maps Scraper Kit](https://github.com/Mahanaicoach/google-maps-scraper-kit) | Local-business discovery adapter; requires compliant source access and provider/API credentials. MIT. |
| [Scout](https://github.com/kiryano/Scout) | Public social/web enrichment research adapter. MIT. |
| [YC Outreach](https://github.com/adityajha2005/yc-outreach) | YC company discovery reference. MIT. |
| [Goose Skills](https://github.com/gooseworks-ai/goose-skills) | Brand-growth and marketing workflow skill reference. MIT. |
| [Growth Engineer](https://github.com/GetBrew/growth-engineer) | Company research and growth-workflow reference. MIT. |
| [Cold Outbound Skills](https://github.com/growthenginenowoslawski/coldoutboundskills) | Public research and outbound copy framework reference. MIT. |
| [Warmbly](https://github.com/warmbly/warmbly) | Warm-up / deliverability concepts; Apache-2.0. Not wired as a provider. |
| [OneShot GTM](https://github.com/oneshot-agent/oneshot-gtm) | GTM workflow and pipeline design reference. MIT. |
| [DeskcommCRM](https://github.com/melgarafael/DeskcommCRM) | CRM workflow reference. MIT. |

## Operational truth / dependencies
- Current Hunter is a bounded passive probe over marketing/seed_leads.csv; it is not yet broad web-scale discovery.
- Reply capture is manual in the mobile inbox form. Automatic reply ingestion requires a monitored mailbox integration or inbound email webhook plus DNS/MX configuration. Do not claim automatic inbox sync until configured and tested.
- GitHub Actions schedules do not require a laptop. Schedules can be delayed by GitHub and are not guaranteed exact-time execution.
- Vercel deployment and production environment variables must be verified separately from repository commits.
- MELLENTH_ADMIN_TOKEN must be set as a Vercel production environment variable before the operator dashboard can be unlocked.
- Marketing consent is explicit and separate from a free assessment request. A discovered email address is not consent.
- The existing outbound follow-up engine is restricted to records with marketing_consent=true.
- Product contracts, prices, delivery capacity, and payment terms must be confirmed before proposals are issued.
