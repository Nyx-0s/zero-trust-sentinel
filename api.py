"""FastAPI endpoints for Zero-Trust Sentinel.

Endpoints:
- POST /scan: Trigger the LangGraph scan (background task).
- GET /report/{id}: Return report data (PDF generation would be separate).
- GET /dashboard/{client_id}: Lightweight JSON dashboard endpoint.
- POST /simulate: Digital Twin breach-trajectory simulation (subscribers only).
- GET /simulate/{client_id}: latest saved trajectory for a subscriber.
- POST /webhook/stripe: Handle payment success, plan changes, and churn/win-back.
- GET /health: Health check endpoint.
- POST /capture: Capture a lead from the landing page (returns client_id for the Native Button).
- POST /checkout: Global-ready checkout (PayPal Subscriptions API, AirTM link fallback).
- POST /checkout/tripwire: Create Stripe Checkout Session - "First 72 Hours Free: Black October Emergency Monitoring".
- POST /webhook/paypal: PayPal webhooks (signature-verified, idempotent, subscription-id lookup).
- POST /webhook/paypal-activate: Activate after Native PayPal Button approval (server-verified).
"""

from __future__ import annotations

import asyncio
import json
import os
import stripe
import httpx
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from main import run_scan
from simulation import simulate_trajectory
from db import (
    create_client,
    get_client_by_domain,
    get_client_by_id,
    create_report,
    init_db,
    get_latest_report,
    create_scan_task,
    get_scan_task,
    update_scan_task,
    is_domain_scanning,
    create_lead_task,
    get_lead_task,
    mark_lead_hot,
    get_hot_leads,
    mark_lead_emailed,
    activate_subscription,
    deactivate_subscription,
    link_paypal_subscription,
    get_client_id_by_subscription,
    save_coupon,
    get_client,
    has_event_processed,
    mark_event_processed,
    is_suppressed,
    get_latest_report_by_domain,
    is_subscribed,
    save_trajectory,
    get_latest_trajectory,
    create_referral,
    get_referral_by_domain,
    apply_referral_discount,
    update_lead_task_status,
    update_lead_task_metadata,
    set_lead_signals,
    get_lead_signals,
    claim_lead_task,
    is_lead_task_stale,
    list_recoverable_lead_tasks,
)
from utils import is_valid_domain, sanitize_domain

# Initialize Stripe with your secret key
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Initialize FastAPI app
app = FastAPI(
    title="Zero-Trust Sentinel API",
    description="Automated External Attack Surface Monitoring for SMBs",
    version="1.0.0",
)

# CORS: the cockpit (static/index.html) may be hosted on Vercel/Netlify while
# the API runs on your server. Default allows any origin (safe: report data is
# public, and activation is verified server-to-server with PayPal regardless
# of browser headers). Lock it down with FRONTEND_ORIGINS=https://a.com,https://b.com
_origins = [o.strip() for o in os.getenv("FRONTEND_ORIGINS", "").split(",") if o.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _paypal_api_base() -> str:
    """PayPal REST base, honoring PAYPAL_MODE=sandbox|live.

    PAYPAL_API_BASE always wins when set. Otherwise PAYPAL_MODE picks the
    environment: sandbox credentials against the live host fail with 401
    invalid_client, so an unset mode defaults to live (the production case).
    """
    explicit = os.getenv("PAYPAL_API_BASE")
    if explicit:
        return explicit
    if os.getenv("PAYPAL_MODE", "live").strip().lower() == "sandbox":
        return "https://api-m.sandbox.paypal.com"
    return "https://api-m.paypal.com"


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    await init_db()


class ScanRequest(BaseModel):
    """Request model for scan validation."""
    domain: str
    client_id: Optional[str] = None


class SimulateRequest(BaseModel):
    """Digital Twin simulation request (subscribers only)."""
    client_id: str
    annual_revenue: Optional[int] = None  # disclosed revenue assumption; None = default


class LeadCapture(BaseModel):
    domain: str
    email: str = ""          # optional: pure discovery leads may have no opt-in email
    name: str = "there"
    signals: List[str] = []  # Harvey discovery signals (exposed_api, staging_exposed, ...)
    harvey_ref: str = ""     # Harvey discovery reference (ties replies to the finding)


def _coerce_client_id(raw: Any) -> Optional[int]:
    """Stripe metadata values are strings; DB client ids are integers."""
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    await init_db()


@app.post("/scan")
async def create_scan(request: ScanRequest) -> Dict[str, Any]:
    """
    Triggers a security scan for the given domain.

    This endpoint starts the scan as a background task and returns
    a task ID for polling. It does NOT block while the scan runs.

    Args:
        request: ScanRequest containing domain and optional client_id.

    Returns:
        Dict with status, message, and task_id for polling.
    """
    domain = sanitize_domain(request.domain)

    # 1. Validation
    if not is_valid_domain(domain):
        return {"status": "error", "message": "Invalid domain format", "task_id": None}

    # 2. Check if already scanning
    if await is_domain_scanning(domain):
        task_id = await get_task_id(domain)
        return {
            "status": "scanning",
            "message": "Scan already in progress",
            "task_id": task_id,
        }

    # 3. Create scan task in DB
    task_id = await create_scan_task(domain, request.client_id)

    # 4. Start background scan
    # Use create_task so the HTTP response returns immediately
    asyncio.create_task(run_scan_background(task_id, domain, request.client_id))

    return {
        "status": "started",
        "message": "Scan initiated",
        "task_id": task_id,
    }


async def run_scan_background(task_id: str, domain: str, client_id: Optional[str]):
    """
    Background task that runs the full scan pipeline and updates the DB.
    """
    try:
        # Run the full scanner (with all guardrails)
        from scanners import run_full_scan
        raw_scan = await run_full_scan(domain)

        if "error" in raw_scan:
            await update_scan_task(task_id, "failed", error=raw_scan["error"])
            return

        # Reports FK references clients.id, so resolve/create a client account
        client = await get_client_by_domain(domain)
        if client:
            client_db_id = client["id"]
        elif client_id and str(client_id).isdigit():
            client_db_id = int(client_id)
        else:
            client_db_id = await create_client(domain)

        # Run LangGraph
        result = await run_scan(domain, client_id=str(client_db_id))

        # Save report
        await create_report(
            client_id=client_db_id,
            risk_score=result.get("risk_score", 100),
            executive_summary=result.get("executive_summary", ""),
            raw_scan=result.get("raw_scan", {}),
            risk_assessment=result.get("risk_assessment", []),
            remediation_plan=result.get("remediation_plan", []),
        )
        await update_scan_task(task_id, "completed")

    except Exception as e:
        await update_scan_task(task_id, "failed", error=str(e))


@app.post("/capture")
async def capture_lead(lead: LeadCapture, ref: Optional[int] = None) -> Dict[str, Any]:
    """
    Captures a lead from the landing page.

    1. Validates domain.
    2. Checks suppression list.
    3. Checks for referral (applies 1-month-free discount if referred).
    4. Triggers a background scan.
    5. Returns a 'scan_id' for the frontend to poll.

    Args:
        lead: LeadCapture containing domain, email, and name.
        ref: Optional referral ID from a referral link.

    Returns:
        Dict with status and scan_id for polling.
    """
    domain = sanitize_domain(lead.domain)

    if not is_valid_domain(domain):
        return {"status": "error", "message": "Invalid domain format"}

    # 1. Check suppression list - never email someone who unsubscribed
    if await is_suppressed(lead.email):
        return {"status": "suppressed", "message": "You are already on our suppression list."}

    # 2. Check for a matching referral for this domain
    referral = await get_referral_by_domain(domain) if ref else None

    # 3. Create (or resolve) the client account SYNCHRONOUSLY so the frontend
    #    gets its client_id now: the Native PayPal Button needs
    #    window.CURRENT_CLIENT_ID before the user can subscribe, and the
    #    background scan would otherwise resolve it later.
    client = await get_client_by_domain(domain)
    if client:
        client_db_id = client["id"]
    else:
        client_db_id = await create_client(domain, email=lead.email, name=lead.name)

    # 3b. Create a task in DB
    task_id = await create_lead_task(domain, lead.email, lead.name)

    # 3b. Persist Harvey discovery signals so the Analyst/Editor prioritize them
    if lead.signals or lead.harvey_ref:
        await set_lead_signals(task_id, lead.signals, lead.harvey_ref)

    # 4. If referred, apply the 1-month-free discount
    #    (coupons FK references clients.id; client exists from step 3)
    if referral:
        await apply_referral_discount(referral["id"], client_db_id)
        print(f"[REFERRAL] Applied discount for {domain} (Referral ID: {referral['id']})")

    # 5. Trigger background scan (signals flow into the LangGraph swarm)
    asyncio.create_task(process_lead_scan(task_id, domain, lead.email, lead.name,
                                           signals=lead.signals))

    return {"status": "started", "scan_id": task_id, "client_id": client_db_id,
            "referral_applied": bool(referral)}


async def _fail_lead_task(task_id: int, error: str) -> None:
    """Mark a lead failed *and record why*.

    lead_tasks has no error column, so before this the Face only ever showed
    "Assessment failed" while the real cause (a Groq 429, a DNS miss) lived
    in stdout nobody could read. metadata.error is that missing message.
    """
    try:
        await update_lead_task_metadata(
            task_id,
            {"error": str(error),
             "failed_at": datetime.utcnow().isoformat(timespec="seconds") + "Z"},
        )
    except Exception as meta_err:
        # Never let bookkeeping hide the failure itself.
        print(f"[LEAD ERROR] task {task_id}: could not persist error: {meta_err}")
    await update_lead_task_status(task_id, "failed")


async def process_lead_scan(task_id: int, domain: str, email: str, name: str,
                            signals: Optional[List[str]] = None):
    """
    Runs the scan and updates the lead's status in the DB.
    If risk_score < 80, marks the lead as 'hot' for the outbound engine.
    signals: Harvey discovery signals threaded into the Analyst/Editor prompts.

    Ownership is a lease, not a promise: the in-process task can die with the
    instance (cloudrun scale-to-zero, redeploy), so every run must first win
    claim_lead_task(), and recovery paths re-dispatch until a run finishes.
    """
    # Lease acquisition. A failed claim means another worker owns this lead -
    # exit silently rather than scan it twice. A claim *error* is left alone so
    # the sweeper can retry instead of marking a healthy lead failed.
    try:
        lead = await get_lead_task(task_id)
        if not lead:
            return
        acquired = await claim_lead_task(task_id, lead.get("updated_at"))
    except Exception as e:
        print(f"[RECOVERY] claim failed for {domain} (task {task_id}): {e}")
        return
    if not acquired:
        return

    if signals is None:
        try:
            signals = await get_lead_signals(domain)
        except Exception:
            signals = []

    try:
        from scanners import run_full_scan
        raw_scan = await run_full_scan(domain)

        if "error" in raw_scan:
            await _fail_lead_task(task_id, raw_scan["error"])
            return

        # Heartbeat: the probe took real time, refresh the lease before the
        # slow LLM step so the sweeper does not double-dispatch a live run.
        await update_lead_task_status(task_id, "running")

        # Reports FK references clients.id, so resolve/create a client account
        client = await get_client_by_domain(domain)
        if client:
            client_db_id = client["id"]
        else:
            client_db_id = await create_client(domain, email=email, name=name)

        # Run LangGraph for full analysis (signals prioritize the Analyst)
        result = await run_scan(domain, client_id=str(client_db_id), signals=signals)

        # Save report against the real client account - but never twice: a
        # recovery run that follows a crash must not duplicate the report.
        if not await get_latest_report_by_domain(domain):
            await create_report(
                client_id=client_db_id,
                risk_score=result.get("risk_score", 100),
                executive_summary=result.get("executive_summary", ""),
                raw_scan=result.get("raw_scan", {}),
                risk_assessment=result.get("risk_assessment", []),
                remediation_plan=result.get("remediation_plan", []),
            )

        # Mark as hot if vulnerable, otherwise complete
        if result.get("risk_score", 100) < 80:
            await mark_lead_hot(task_id, email, name)
            print(f"[LEAD] {domain} is HOT (Score: {result['risk_score']}). Added to priority queue.")
        else:
            await update_lead_task_status(task_id, "completed")

    except Exception as e:
        print(f"[LEAD ERROR] {domain}: {e}")
        await _fail_lead_task(task_id, e)


# -- Lead scan durability -----------------------------------------------------
# The Face's /capture returns immediately and the work runs in-process, which
# is exactly what dies on a scale-to-zero Deployment. These three paths bring
# stranded scans back: startup (after a redeploy), every /task poll (the Face
# polls until terminal), and a slow periodic sweep for unpolled leads.

LEAD_PENDING_STALE_SECONDS = 45    # a fresh capture is never stale (Face polls ~2s)
LEAD_RUNNING_STALE_SECONDS = 900   # analysis lease, refreshed by the heartbeat
LEAD_SWEEP_INTERVAL_SECONDS = 60
_lead_sweep_task: Optional[asyncio.Task] = None


async def _dispatch_lead_scan(task_id: int, domain: str, email: str,
                              name: str) -> None:
    """Start (or re-start) a lead scan. The claim inside decides ownership."""
    signals = await get_lead_signals(domain)
    asyncio.create_task(process_lead_scan(task_id, domain, email, name,
                                          signals=signals))


async def recover_stale_lead_scans(limit: int = 5) -> int:
    """Re-queue lead scans whose in-process worker died. Returns resumed count."""
    try:
        stale = await list_recoverable_lead_tasks(
            pending_after=LEAD_PENDING_STALE_SECONDS,
            running_after=LEAD_RUNNING_STALE_SECONDS,
            limit=limit,
        )
    except Exception as e:
        print(f"[RECOVERY] sweep failed: {e}")
        return 0
    for lead in stale:
        print(f"[RECOVERY] resuming stranded lead scan: task {lead['id']} "
              f"{lead.get('domain')} (last seen {lead.get('updated_at')})")
        await _dispatch_lead_scan(lead["id"], lead.get("domain") or "",
                                  lead.get("email") or "",
                                  lead.get("name") or "there")
    return len(stale)


async def _lead_sweep_loop() -> None:
    while True:
        await asyncio.sleep(LEAD_SWEEP_INTERVAL_SECONDS)
        await recover_stale_lead_scans()


_last_lead_sweep: float = float("-inf")   # first poll always sweeps


async def _maybe_sweep_stale_lead_scans() -> None:
    """Run the cross-lead sweep at most once per interval.

    Driven by /task polls so a stranded lead with no poller of its own
    (a Hunter-ingested lead) is reclaimed by other traffic, instead of
    waiting for the periodic loop or a restart.
    """
    global _last_lead_sweep
    now = asyncio.get_event_loop().time()
    if now - _last_lead_sweep < LEAD_SWEEP_INTERVAL_SECONDS:
        return
    _last_lead_sweep = now   # set first: overlapping polls never double-sweep
    n = await recover_stale_lead_scans()
    if n:
        print(f"[RECOVERY] poll-driven sweep resumed {n} lead scan(s)")


@app.on_event("startup")
async def start_lead_recovery() -> None:
    """Drain stranded scans left by the previous instance, then keep sweeping."""
    global _lead_sweep_task
    await recover_stale_lead_scans()
    _lead_sweep_task = asyncio.create_task(_lead_sweep_loop())


@app.on_event("shutdown")
async def stop_lead_recovery() -> None:
    if _lead_sweep_task is not None:
        _lead_sweep_task.cancel()


def _signal_note(signals: List[str]) -> str:
    """Signal-aware context for public reports (Harvey-triggered scans)."""
    notes = []
    for signal in signals:
        if signal in ("exposed_api", "public_api", "api_docs"):
            notes.append("Given your public API, this exposure is high-risk.")
        elif signal in ("staging_exposed", "staging_subdomain"):
            notes.append("Your exposed staging/dev environment was independently observed in DNS.")
        elif signal == "outdated_security":
            notes.append("Your published security page has not been updated in over a year.")
        elif signal == "running_ads":
            notes.append("You are currently paying for traffic to this surface, so trust and uptime matter immediately.")
        elif signal == "custom_domain":
            notes.append("Your branded production domain makes this surface part of your customer-facing trust chain.")
    if not notes:
        notes.append("This report prioritizes findings confirmed by independent discovery signals.")
    return " ".join(notes)


@app.post("/checkout")
async def create_checkout_session(client_id: str, plan: str = "monthly") -> Dict[str, Any]:
    """
    Global-ready checkout for an India-based merchant (Stripe is not used here).

    Provider priority:
      1. PayPal Subscriptions API (PAYPAL_CLIENT_ID, PAYPAL_SECRET, PAYPAL_PLAN_ID)
         - documented for India, international/cross-border payments only.
      2. AirTM hosted payment link (AIRTM_PAYMENT_LINK) for manual recurring billing.

    Returns:
        Dict with the checkout URL and provider name.
    """
    paypal_client_id = os.getenv("PAYPAL_CLIENT_ID")
    paypal_secret = os.getenv("PAYPAL_SECRET")
    paypal_plan_id = os.getenv("PAYPAL_PLAN_ID")

    if paypal_client_id and paypal_secret and paypal_plan_id:
        base = _paypal_api_base()
        site = os.getenv("SITE_URL", "http://localhost:8000")
        async with httpx.AsyncClient(timeout=30) as http:
            token_resp = await http.post(
                f"{base}/v1/oauth2/token",
                auth=(paypal_client_id, paypal_secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                return {"error": f"PayPal auth failed ({token_resp.status_code})"}
            token = token_resp.json().get("access_token")

            sub_resp = await http.post(
                f"{base}/v1/billing/subscriptions",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
                json={
                    "plan_id": paypal_plan_id,
                    "custom_id": str(client_id),
                    "application_context": {
                        "brand_name": "Zero-Trust Sentinel",
                        "return_url": f"{site}/success?client_id={client_id}",
                        "cancel_url": f"{site}/cancel",
                        "user_action": "SUBSCRIBE_NOW",
                    },
                },
            )
            if sub_resp.status_code not in (200, 201):
                return {"error": f"PayPal subscription create failed ({sub_resp.status_code})"}

            subscription = sub_resp.json()
            approve_url = next(
                (link.get("href") for link in subscription.get("links", [])
                 if link.get("rel") == "approve"),
                None,
            )
            if not approve_url:
                return {"error": "PayPal approval link missing"}
            return {"url": approve_url, "provider": "paypal",
                    "subscription_id": subscription.get("id", "")}

    airm_link = os.getenv("AIRTM_PAYMENT_LINK")
    if airm_link:
        return {"url": airm_link, "provider": "airtm"}

    return {"error": "No payment provider configured. Set "
                     "PAYPAL_CLIENT_ID/PAYPAL_SECRET/PAYPAL_PLAN_ID "
                     "or AIRTM_PAYMENT_LINK."}


@app.post("/checkout/tripwire")
async def create_tripwire_checkout(client_id: str) -> Dict[str, str]:
    """
    Creates a Stripe Checkout Session with a 72-hour free trial.
    Offer: "First 72 Hours Free: Black October Emergency Monitoring".
    This is a SUBSCRIPTION, not a one-time payment.
    The customer gets 72 hours free, then renews at full price.

    Args:
        client_id: The client's database ID.

    Returns:
        Dict with the checkout URL.
    """
    monthly_price_id = os.getenv("PRICE_ID_MONTHLY")

    if not monthly_price_id:
        return {"error": "Monthly price ID not configured"}

    # Get the client to find their domain
    client = await get_client(client_id)
    domain = client.get("domain") if client else ""

    # Create or retrieve a customer
    customer_email = client.get("email") if client else ""
    customer = await stripe.Customer.create(
        email=customer_email,
        metadata={"client_id": client_id, "domain": domain}
    )

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer.id,
        line_items=[
            {
                "price": monthly_price_id,
                "quantity": 1,
            }
        ],
        success_url=f"{os.getenv('SITE_URL', 'https://yourdomain.com')}/success?client_id={client_id}",
        cancel_url=f"{os.getenv('SITE_URL', 'https://yourdomain.com')}/cancel",
        metadata={
            "client_id": client_id,
            "plan": "monthly"
        },
        subscription_data={
            # 72-hour free trial (Black October Emergency Monitoring offer),
            # then the first invoice bills at full price.
            "trial_period_days": 3,
            "metadata": {
                "client_id": client_id
            }
        }
    )

    return {"url": session.url}


@app.post("/webhook/stripe")
async def stripe_webhook(request: Request) -> Dict[str, Any]:
    """
    Handles Stripe webhooks with idempotency and signature verification.
    Prevents duplicate processing of the same event.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    # 1. Verify Signature
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, os.getenv("STRIPE_WEBHOOK_SECRET"))
    except ValueError as e:
        return {"error": f"Invalid payload: {str(e)}"}
    except WebhookSignatureVerificationError as e:
        return {"error": f"Invalid signature: {str(e)}"}

    # 2. Idempotency Check (Prevent duplicate processing)
    event_id = event["id"]
    if await has_event_processed(event_id):
        return {"received": True, "duplicate": True}

    event_type = event["type"]
    data_object = event["data"]["object"]

    # 3. Mark event as processed BEFORE business logic (atomic guarantee)
    client_id = _coerce_client_id(data_object.get("metadata", {}).get("client_id"))
    await mark_event_processed(event_id, event_type, client_id)

    # 4. Process Event
    if event_type == "checkout.session.completed":
        client_id = _coerce_client_id(data_object.get("metadata", {}).get("client_id"))
        plan = data_object.get("metadata", {}).get("plan", "monthly")

        if client_id:
            await activate_subscription(client_id, plan)
            print(f"[STRIPE] Subscription activated for {client_id} ({plan})")

    elif event_type == "customer.subscription.updated":
        subscription = data_object
        client_id = _coerce_client_id(subscription.get("metadata", {}).get("client_id"))

        if client_id:
            # Handle plan changes, etc.
            current_plan = subscription.get("plan", {}).get("id", "monthly")
            await activate_subscription(client_id, current_plan)
            print(f"[STRIPE] Subscription updated for {client_id} ({current_plan})")

    elif event_type == "customer.subscription.deleted":
        client_id = _coerce_client_id(data_object.get("metadata", {}).get("client_id"))
        if client_id:
            await deactivate_subscription(client_id)
            # The lifecycle win-back is sent ONLY by win_back_cron.py after the
            # 30-day silence period (never immediately after cancellation).
            print(f"[STRIPE] Subscription cancelled for {client_id}. Win-back queued for 30-day cron.")

    return {"received": True}


async def _verify_paypal_webhook(request: Request, event: dict) -> bool:
    """Verifies PayPal transmission headers via VERIFY-WEBHOOK-SIGNATURE."""
    client_id = os.getenv("PAYPAL_CLIENT_ID")
    secret = os.getenv("PAYPAL_SECRET")
    webhook_id = os.getenv("PAYPAL_WEBHOOK_ID")
    if not (client_id and secret and webhook_id):
        print("[PAYPAL] webhook verification not configured "
              "(PAYPAL_CLIENT_ID / PAYPAL_SECRET / PAYPAL_WEBHOOK_ID)")
        return False

    base = _paypal_api_base()
    async with httpx.AsyncClient(timeout=15) as http:
        token_resp = await http.post(
            f"{base}/v1/oauth2/token",
            auth=(client_id, secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            return False
        token = token_resp.json().get("access_token")

        verify_resp = await http.post(
            f"{base}/v1/notifications/verify-webhook-signature",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            json={
                "auth_algo": request.headers.get("paypal-auth-algo"),
                "cert_url": request.headers.get("paypal-cert-url"),
                "transmission_id": request.headers.get("paypal-transmission-id"),
                "transmission_sig": request.headers.get("paypal-transmission-sig"),
                "transmission_time": request.headers.get("paypal-transmission-time"),
                "webhook_id": webhook_id,
                "webhook_event": event,
            },
        )
        if verify_resp.status_code != 200:
            return False
        return verify_resp.json().get("verification_status") == "SUCCESS"


async def _paypal_get_subscription(subscription_id: str) -> Optional[Dict[str, Any]]:
    """Fetches a subscription from PayPal (server-to-server) for verification.

    Returns the subscription JSON, or None when PayPal is unconfigured,
    unreachable, or does not know the subscription (404).
    """
    client_id = os.getenv("PAYPAL_CLIENT_ID")
    secret = os.getenv("PAYPAL_SECRET")
    if not (client_id and secret):
        return None

    base = _paypal_api_base()
    async with httpx.AsyncClient(timeout=15) as http:
        token_resp = await http.post(
            f"{base}/v1/oauth2/token",
            auth=(client_id, secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            return None
        token = token_resp.json().get("access_token")

        resp = await http.get(
            f"{base}/v1/billing/subscriptions/{subscription_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            return None
        return resp.json()


@app.post("/webhook/paypal-activate")
async def paypal_native_activate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Activates a client after they approve the Native PayPal Subscribe Button.

    Called by the landing-page frontend (onApprove) with the subscription id
    PayPal returned in the browser. The browser is UNTRUSTED, so this endpoint
    verifies the subscription server-to-server before activating anything:

      1. The subscription exists at PayPal (GET /v1/billing/subscriptions/{id}).
      2. Its status is ACTIVE or APPROVED.
      3. Its plan matches PAYPAL_PLAN_ID (i.e. our $49/mo plan).
      4. If PayPal recorded a custom_id, it must match the requested client
         (prevents activating someone else's account with your subscription).

    Idempotent: PayPal ALSO sends BILLING.SUBSCRIPTION.ACTIVATED to
    /webhook/paypal; both paths converge on the same subscription row.
    """
    subscription_id = (payload.get("subscription_id") or "").strip()
    requested_client_id = _coerce_client_id(payload.get("client_id"))

    if not subscription_id or requested_client_id is None:
        return JSONResponse(status_code=400,
                            content={"error": "Missing subscription_id or client_id"})

    client = await get_client_by_id(requested_client_id)
    if not client:
        return JSONResponse(status_code=404, content={"error": "Client not found"})

    sub = await _paypal_get_subscription(subscription_id)
    if sub is None:
        return JSONResponse(status_code=402,
                            content={"error": "PayPal subscription not found "
                                              "(or PayPal is unconfigured/unreachable)"})

    sub_status = (sub.get("status") or "").upper()
    if sub_status not in ("ACTIVE", "APPROVED"):
        return JSONResponse(status_code=402,
                            content={"error": f"Subscription status is {sub_status or 'unknown'}, not active"})

    plan_id = os.getenv("PAYPAL_PLAN_ID")
    sub_plan = sub.get("plan_id") or ""
    if plan_id and sub_plan and sub_plan != plan_id:
        return JSONResponse(status_code=402,
                            content={"error": "Subscription is not on the $49/mo plan"})

    sub_custom = _coerce_client_id(sub.get("custom_id"))
    if sub_custom is not None and sub_custom != requested_client_id:
        return JSONResponse(status_code=403,
                            content={"error": "Subscription belongs to a different client"})

    await link_paypal_subscription(requested_client_id, subscription_id)
    await activate_subscription(requested_client_id, "monthly")
    print(f"[PAYPAL] Native subscription {subscription_id} activated for client "
          f"{requested_client_id} ({client.get('domain', '?')})")
    return {"status": "active", "message": "Monitoring activated."}


@app.post("/webhook/paypal")
async def paypal_webhook(request: Request) -> Dict[str, Any]:
    """
    PayPal webhook: signature-verified and idempotent.

    Handled events:
      BILLING.SUBSCRIPTION.ACTIVATED -> activate $49/mo subscription
      PAYMENT.CAPTURE.COMPLETED      -> payment captured -> activate
      BILLING.SUBSCRIPTION.CANCELLED -> deactivate (30-day cron owns re-engagement)

    PAYPAL_SKIP_SIGNATURE_VERIFY=1 disables verification for LOCAL SIMULATION ONLY.
    """
    payload = await request.body()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return {"error": "Invalid payload"}

    event_id = event.get("event_id") or event.get("id")
    event_type = event.get("event_type", "")

    # 1. Verify the PayPal transmission signature (unless simulating locally)
    if os.getenv("PAYPAL_SKIP_SIGNATURE_VERIFY") != "1":
        if not await _verify_paypal_webhook(request, event):
            return JSONResponse(status_code=403,
                                content={"error": "Signature verification failed"})

    if not event_id:
        return {"error": "Missing event id"}

    # 2. Idempotency (shared stripe_events table: event ids are unique per provider)
    if await has_event_processed(event_id):
        return {"received": True, "duplicate": True}

    resource = event.get("resource") or {}

    # Native Button subscriptions carry NO custom_id in webhooks: resolve the
    # client from the subscription id linked at /webhook/paypal-activate time.
    subscription_id = ""
    if event_type.startswith("BILLING.SUBSCRIPTION"):
        subscription_id = resource.get("id") or ""
    elif event_type.startswith("PAYMENT."):
        # Capture events reference the subscription via billing_agreement_id
        subscription_id = resource.get("billing_agreement_id") or ""

    client_id = _coerce_client_id(
        resource.get("custom_id")
        or resource.get("custom")
        or (resource.get("metadata") or {}).get("client_id")
    )
    if client_id is None and subscription_id:
        client_id = await get_client_id_by_subscription(subscription_id)

    await mark_event_processed(event_id, event_type, client_id)

    # 3. Business logic
    if event_type in ("BILLING.SUBSCRIPTION.ACTIVATED", "PAYMENT.CAPTURE.COMPLETED"):
        if client_id:
            if subscription_id:
                await link_paypal_subscription(client_id, subscription_id)
            await activate_subscription(client_id, "monthly")
            print(f"[PAYPAL] Subscription activated for {client_id} ({event_type})")
    elif event_type in ("BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.EXPIRED",
                        "BILLING.SUBSCRIPTION.PAYMENT.FAILED"):
        if client_id:
            await deactivate_subscription(client_id)
            # Lifecycle win-back is sent ONLY by win_back_cron.py (30-day silence)
            print(f"[PAYPAL] Subscription {event_type} for {client_id}. "
                  "Deactivated; win-back queued for 30-day cron.")

    return {"received": True}


async def send_win_back_email(client_id):
    """
    Sends a personalized win-back email with specific risk data.
    Accepts a client id as int or numeric string (Stripe metadata).
    """
    from db import get_client as db_get_client
    client_id = _coerce_client_id(client_id)
    if client_id is None:
        return
    client = await db_get_client(client_id)
    if not client:
        return

    domain = client.get("domain")
    email = client.get("email")
    name = client.get("name", "there")

    # Get the latest report for specific risk data
    from db import get_latest_report
    last_report = await get_latest_report(client_id)

    # Extract specific risk from their last scan
    risk_title = "General Security Issues"
    risk_impact = "Potential data exposure"
    if last_report and last_report.get("risk_assessment"):
        top_risk = last_report["risk_assessment"][0]
        risk_title = top_risk.get("title", "Security Risk")
        risk_impact = top_risk.get("business_impact", "Business impact unknown")

    # Generate a unique discount code
    discount_code = f"WELCOME20-{str(client_id)[:8]}"

    # Create a Stripe Coupon - 20% off repeating for 3 months
    coupon = stripe.Coupon.create(
        percent_off=20,
        duration="repeating",
        duration_in_months=3,
        max_redemptions=1,
        metadata={"client_id": client_id}
    )

    # Save the coupon to DB for reference
    await save_coupon(client_id, coupon.id)

    # Get the current price ID for the renewal reference
    price_id = os.getenv("PRICE_ID_MONTHLY", "")

    subject = f"Your security monitoring for {domain} has stopped"

    body = f"""Hi {name},

Your Zero-Trust Sentinel monitoring for {domain} has been cancelled.

We hate to see you go. Your last risk score was {last_report.get('risk_score', 'N/A') if last_report else 'N/A'}/100.

**Top Risk Identified:** {risk_title}
**Business Impact:** {risk_impact}

If you change your mind, we'd love to have you back. Use code {discount_code} for 20% off your next 3 months.

After 3 months, your subscription will renew at $49/month.

[Reactivate with 20% Discount]

[Your Name]
Zero-Trust Sentinel
"""

    # Send via SendGrid (preferred) with Resend as fallback - same provider
    # choice as outbound_engine._send_email.
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
    RESEND_API_KEY = os.getenv("RESEND_API_KEY")
    FROM_EMAIL = os.getenv("FROM_EMAIL", "security@zerodaysentinel.xo.je")

    if not SENDGRID_API_KEY and not RESEND_API_KEY:
        print("[WARN] SENDGRID_API_KEY/RESEND_API_KEY not set, win-back email skipped")
        return

    html = body.replace("\n", "<br>")
    if SENDGRID_API_KEY:
        # SendGrid v3 mail/send - answers 202 Accepted
        url = "https://api.sendgrid.com/v3/mail/send"
        headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}"}
        payload = {
            "personalizations": [{"to": [{"email": email}]}],
            "from": {"email": FROM_EMAIL},
            "subject": subject,
            "content": [{"type": "text/html", "value": html}],
        }
    else:
        url = "https://api.resend.com/emails"
        headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
        payload = {
            "from": FROM_EMAIL,
            "to": [email],
            "subject": subject,
            "html": html,
        }

    async with httpx.AsyncClient() as client_http:
        try:
            response = await client_http.post(url, headers=headers, json=payload)
            if response.status_code in (200, 202):   # SendGrid answers 202
                print(f"[WIN-BACK EMAIL] Sent to {email}")
            else:
                print(f"[WIN-BACK EMAIL FAIL] {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[WIN-BACK EMAIL ERROR] {e}")


@app.get("/task/{task_id}")
async def get_task(task_id: str) -> Dict[str, Any]:
    """
    Poll endpoint for scan progress (used by the landing page and public report).

    Lead-capture scans use numeric lead_tasks ids; /scan background jobs
    use scan_tasks UUIDs.
    """
    if task_id.isdigit():
        lead = await get_lead_task(int(task_id))
        if lead:
            # The Face polls until a terminal state, so each poll is a chance
            # to resume a scan whose in-process worker died (scale-to-zero,
            # redeploy, crash). The claim inside decides who owns the rerun.
            try:
                stale = await is_lead_task_stale(
                    int(task_id),
                    pending_after=LEAD_PENDING_STALE_SECONDS,
                    running_after=LEAD_RUNNING_STALE_SECONDS,
                )
            except Exception:
                stale = False
            if stale:
                print(f"[RECOVERY] /task/{task_id}: resuming stranded lead scan")
                await _dispatch_lead_scan(int(task_id), lead["domain"],
                                          lead.get("email") or "",
                                          lead.get("name") or "there")
            await _maybe_sweep_stale_lead_scans()
            return {
                "status": lead["status"],
                "domain": lead["domain"],
                "scan_id": int(task_id),
            }

    task = await get_scan_task(task_id)
    if not task:
        return JSONResponse(status_code=404, content={"error": "Task not found"})

    return {
        "status": task["status"],
        "domain": task["domain"],
        "error": task.get("error"),
    }


@app.get("/report/{report_id:int}")
async def get_report(report_id: int) -> FileResponse:
    """Retrieve a generated report by ID."""
    from db import get_report_by_id

    report = await get_report_by_id(report_id)
    if not report:
        return JSONResponse(status_code=404, content={"error": "Report not found"})

    pdf_path = report.get("pdf_path")
    if pdf_path and pdf_path != "":
        try:
            return FileResponse(pdf_path, media_type="application/pdf", filename=f"report_{report_id}.pdf")
        except Exception:
            pass

    # If no PDF path available, return report data
    return JSONResponse(status_code=200, content=report)


@app.get("/report/{domain}")
async def get_public_report(domain: str) -> Dict[str, Any]:
    """
    Generates a public-facing 'Security Posture' report for a domain.

    Used for the shareable content-marketing lead magnet. Serves a recent
    report if one exists; otherwise triggers a background scan and returns
    a 'scanning' status for the frontend to poll.
    """
    domain = sanitize_domain(domain)

    if not is_valid_domain(domain):
        return {"status": "error", "message": "Invalid domain format"}

    # Check if we have a recent report (last 24h)
    report = await get_latest_report_by_domain(domain)

    if report:
        created_at = report.get("created_at")
        if created_at and (datetime.utcnow() - created_at).total_seconds() < 86400:
            signals = await get_lead_signals(domain)
            payload = {
                "status": "completed",
                "risk_score": report["risk_score"],
                "top_risks": (report.get("risk_assessment") or [])[:3],
                "remediation_plan": (report.get("remediation_plan") or [])[:3],
                "last_scan": report["created_at"],
            }
            if signals:
                payload["signals"] = signals
                payload["signal_note"] = _signal_note(signals)
            return payload

    # Trigger a background scan (public visitor - no email collected)
    task_id = await create_lead_task(domain, "", "Public Visitor")
    asyncio.create_task(process_lead_scan(task_id, domain, "", "Public Visitor"))
    return {"status": "scanning", "task_id": task_id}


@app.post("/refer")
async def create_referral_link(referrer_id: str, referred_domain: str) -> Dict[str, Any]:
    """
    Creates a referral. If the referred domain signs up, the referrer gets
    1 month free (two-sided referral loop).
    """
    # Validate referrer (FastAPI query params arrive as strings)
    referrer_id_int = _coerce_client_id(referrer_id)
    if referrer_id_int is None:
        return {"error": "Invalid referrer ID"}
    referrer = await get_client(referrer_id_int)
    if not referrer:
        return {"error": "Referrer not found"}

    # Validate referred domain
    referred_domain = sanitize_domain(referred_domain)
    if not is_valid_domain(referred_domain):
        return {"error": "Invalid domain format"}

    # Create referral record
    referral_id = await create_referral(referrer_id_int, referred_domain)

    # Generate a unique referral link
    referral_link = f"https://yourdomain.com/capture?domain={referred_domain}&ref={referral_id}"

    return {"referral_link": referral_link, "referral_id": referral_id}


@app.get("/dashboard/{client_id}")
async def get_dashboard(client_id: str) -> Dict[str, Any]:
    """Returns the latest risk score and top risks for a client."""
    # Path params arrive as strings; the DB layer needs an int (the Native
    # Button's onApprove redirects straight to this endpoint).
    client_id_int = _coerce_client_id(client_id)
    if client_id_int is None:
        return JSONResponse(status_code=400, content={"error": "Invalid client id"})

    # get_latest_report includes risk_assessment; list_reports_by_client does
    # not (it is a summary list), so use it here or top_risks would KeyError.
    report = await get_latest_report(client_id_int)

    if not report:
        return {"error": "No report found", "risk_score": 100}

    return {
        "risk_score": report["risk_score"],
        "last_scan": report["created_at"],
        "top_risks": (report.get("risk_assessment") or [])[:3],
        "status": "active",
    }


@app.post("/simulate")
async def run_digital_twin(request: SimulateRequest) -> Dict[str, Any]:
    """Digital Twin: a 50-round breach-trajectory simulation (subscribers only).

    Seeded from the client's REAL latest scan - findings and severities are
    inputs; the trajectory (time to detect/contain, impact window, modeled
    revenue exposure, mitigation deltas) is a labeled model, computed from
    assumptions that ship inside the payload. Nothing is invented.

    Gating mirrors the pricing ladder: the simulation is part of the
    $49/mo monitoring tier, not the $1.99/$9.99 triage layer.
    """
    client_id = _coerce_client_id(request.client_id)
    if client_id is None:
        return JSONResponse(status_code=400, content={"error": "Invalid client id"})

    client = await get_client_by_id(client_id)
    if not client:
        return JSONResponse(status_code=404, content={"error": "Client not found"})

    if not await is_subscribed(client_id):
        return JSONResponse(status_code=403, content={
            "error": "Digital Twin simulations run on active monitoring ($49/mo)",
            "upgrade": "subscribe",
        })

    report = await get_latest_report(client_id)
    if not report:
        return JSONResponse(status_code=404, content={
            "error": "No scan data found. Please run a free scan first.",
        })

    trajectory = simulate_trajectory(
        risk_score=report.get("risk_score", 100),
        findings=report.get("risk_assessment") or [],
        raw_scan=report.get("raw_scan") or {},
        domain=client.get("domain", ""),
        annual_revenue=request.annual_revenue,
    )
    trajectory_id = await save_trajectory(client_id, trajectory)

    return {"status": "completed", "trajectory_id": trajectory_id, **trajectory}


@app.get("/simulate/{client_id}")
async def get_digital_twin(client_id: str) -> Dict[str, Any]:
    """Latest saved Digital Twin trajectory for a subscriber."""
    client_id_int = _coerce_client_id(client_id)
    if client_id_int is None:
        return JSONResponse(status_code=400, content={"error": "Invalid client id"})
    if not await is_subscribed(client_id_int):
        return JSONResponse(status_code=403, content={
            "error": "Digital Twin simulations run on active monitoring ($49/mo)",
            "upgrade": "subscribe",
        })
    saved = await get_latest_trajectory(client_id_int)
    if not saved:
        return JSONResponse(status_code=404, content={
            "error": "No trajectory yet. Run a scan, then POST /simulate.",
        })
    return {"status": "completed", "trajectory_id": saved["id"],
            "created_at": saved["created_at"], **(saved.get("payload") or {})}


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "zero-trust-sentinel"}


@app.exception_handler(Exception)
async def generic_exception_handler(request: Any, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "service": "zero-trust-sentinel"},
    )


# -----------------------------------------------------------------------------
# The "Cockpit": a self-contained landing page (no build step) served by the
# API itself. Registered LAST so every API route above wins over the catch-all.
# It can also be hosted separately (Vercel/Netlify) - point its API_BASE at
# this server; CORS is handled by FRONTEND_ORIGINS above.
# -----------------------------------------------------------------------------
app.mount("/", StaticFiles(directory="static", html=True), name="static")