"""Neon Postgres database connection and table creation for Zero-Trust Sentinel.

Tables:
- clients: stores registered client domains and metadata
- reports: stores generated scan reports
- lead_tasks: stores lead capture tasks
- subscriptions: stores subscription status
- coupons: stores coupon codes for win-back
- stripe_events: tracks processed Stripe events for idempotency
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, List, Optional

import asyncpg

# Database connection pool
_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the database connection pool."""
    global _pool
    if _pool is None:
        database_url = os.getenv("DATABASE_URL")
        if not database_url:
            raise ValueError("DATABASE_URL environment variable not set")
        # Managed Postgres (Render, Neon) requires SSL, but asyncpg only
        # enables it when the URL says so. Add sslmode=require for remote
        # hosts when unset; localhost dev databases are left untouched.
        if database_url.startswith(("postgres://", "postgresql://")) and "sslmode=" not in database_url:
            host = database_url.split("@")[-1].split("/")[0].split(":")[0]
            if host not in ("localhost", "127.0.0.1"):
                database_url += ("&" if "?" in database_url else "?") + "sslmode=require"
        _pool = await asyncpg.create_pool(database_url, min_size=1, max_size=10)
        # JSONB columns (risk_assessment, raw_scan, payload, ...) decode to
        # real dicts/lists; without this they arrive as strings and every
        # consumer silently misbehaves (e.g. report.top_risks[:3] slices a
        # string). Existing writers pass json.dumps(...), so the encoder
        # passes strings through untouched.
        async with _pool.acquire() as _conn:
            await _conn.set_type_codec(
                "jsonb", encoder=lambda v: v if isinstance(v, str) else json.dumps(v),
                decoder=json.loads, schema="pg_catalog")
            await _conn.set_type_codec(
                "json", encoder=lambda v: v if isinstance(v, str) else json.dumps(v),
                decoder=json.loads, schema="pg_catalog")
    return _pool


async def close_pool() -> None:
    """Close the database connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def init_db() -> None:
    """Initialize database tables: clients, reports, lead_tasks, subscriptions, coupons, stripe_events."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Create clients table
        await conn.execute("""CREATE TABLE IF NOT EXISTS clients (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255) UNIQUE NOT NULL,
            risk_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW(),
            last_scan TIMESTAMP DEFAULT NOW(),
            status VARCHAR(50) DEFAULT 'active',
            name VARCHAR(255),
            email VARCHAR(255)
        )""")

        # Create reports table
        await conn.execute("""CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            risk_score INTEGER DEFAULT 0,
            executive_summary TEXT,
            raw_scan JSONB,
            risk_assessment JSONB,
            remediation_plan JSONB,
            pdf_path VARCHAR(500),
            created_at TIMESTAMP DEFAULT NOW()
        )""")

        # Create lead_tasks table
        await conn.execute("""CREATE TABLE IF NOT EXISTS lead_tasks (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255),
            email VARCHAR(255),
            name VARCHAR(255),
            status VARCHAR(50) DEFAULT 'pending'
        )""")

        # Create subscriptions table
        await conn.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            stripe_subscription_id VARCHAR(255) UNIQUE,
            plan VARCHAR(50) DEFAULT 'monthly',
            status VARCHAR(50) DEFAULT 'active',
            current_period_start TIMESTAMP,
            current_period_end TIMESTAMP,
            cancelled_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )""")

        # Create coupons table
        await conn.execute("""CREATE TABLE IF NOT EXISTS coupons (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            stripe_coupon_id VARCHAR(255) UNIQUE,
            percent_off INTEGER DEFAULT 0,
            duration VARCHAR(50) DEFAULT 'repeating',
            duration_in_months INTEGER DEFAULT 3,
            redeemed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )""")

        # Create stripe_events table for webhook idempotency
        await conn.execute("""CREATE TABLE IF NOT EXISTS stripe_events (
            event_id VARCHAR(255) PRIMARY KEY,
            event_type VARCHAR(255),
            client_id INTEGER REFERENCES clients(id),
            processed_at TIMESTAMP DEFAULT NOW()
        )""")

        # Create lead_stages table for follow-up tracking.
        # lead_id has NO foreign key: rows are keyed either by lead_tasks.id
        # (follow-up stages) or by clients.id (win_back stage from the cron).
        await conn.execute("""CREATE TABLE IF NOT EXISTS lead_stages (
            id SERIAL PRIMARY KEY,
            lead_id INTEGER NOT NULL,
            stage VARCHAR(50),
            sent_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(lead_id, stage)
        )""")
        # Drop the legacy FK if an earlier schema created it (idempotent).
        await conn.execute("ALTER TABLE lead_stages DROP CONSTRAINT IF EXISTS lead_stages_lead_id_fkey")

        # Create referrals table for the referral loop
        await conn.execute("""CREATE TABLE IF NOT EXISTS referrals (
            id SERIAL PRIMARY KEY,
            referrer_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            referred_domain VARCHAR(255),
            created_at TIMESTAMP DEFAULT NOW()
        )""")

        # Create scan_tasks table (polling for /scan background jobs)
        await conn.execute("""CREATE TABLE IF NOT EXISTS scan_tasks (
            task_id VARCHAR(64) PRIMARY KEY,
            domain VARCHAR(255),
            client_id VARCHAR(255),
            status VARCHAR(50) DEFAULT 'running',
            error TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )""")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_tasks_domain ON scan_tasks(domain)")

        # Idempotent column additions: PayPal Native Button subscriptions are
        # created client-side (plan-level), so the webhook only carries the
        # subscription id - we must be able to map it back to a client.
        await conn.execute("ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS paypal_subscription_id VARCHAR(255) UNIQUE")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_paypal_id ON subscriptions(paypal_subscription_id)")

        # Idempotent column additions for referral and follow-up tracking
        await conn.execute("ALTER TABLE lead_tasks ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()")
        await conn.execute("ALTER TABLE lead_tasks ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb")
        await conn.execute("ALTER TABLE coupons ADD COLUMN IF NOT EXISTS max_redemptions INTEGER")
        await conn.execute("ALTER TABLE coupons ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb")

        # Public reports are keyed by domain (clients or lead_task scans)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_client_id ON reports(client_id)")

        # Digital Twin trajectories (modeled breach simulations, subscribers only)
        await conn.execute("""CREATE TABLE IF NOT EXISTS trajectories (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
            payload JSONB,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_trajectories_client_id ON trajectories(client_id)")


async def create_client(domain: str, email: str = "", name: str = "") -> int:
    """Create a new client record. Returns the client ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO clients (domain, email, name, status) VALUES ($1, $2, $3, 'active') RETURNING id",
            domain, email, name,
        )
        return row["id"] if row else 0


async def get_client_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Get client record by domain."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM clients WHERE domain = $1", domain)
        if row:
            return {"id": row["id"], "domain": row["domain"], "risk_score": row["risk_score"],
                    "created_at": row["created_at"], "last_scan": row["last_scan"],
                    "status": row["status"], "name": row.get("name", ""), "email": row.get("email", "")}
        return None


async def get_client_by_id(client_id: int) -> Optional[Dict[str, Any]]:
    """Get client record by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM clients WHERE id = $1", client_id)
        if row:
            return {"id": row["id"], "domain": row["domain"], "risk_score": row["risk_score"],
                    "created_at": row["created_at"], "last_scan": row["last_scan"],
                    "status": row["status"], "name": row.get("name", ""), "email": row.get("email", "")}
        return None


async def update_client_scan(client_id: int, risk_score: int, raw_scan: Dict[str, Any]) -> None:
    """Update client's risk score and last scan time."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE clients SET risk_score = $1, last_scan = NOW() WHERE id = $2",
            risk_score, client_id,
        )


async def create_report(
    client_id: int,
    risk_score: int,
    executive_summary: str,
    raw_scan: Dict[str, Any],
    risk_assessment: List[Dict[str, Any]],
    remediation_plan: List[Dict[str, Any]],
    pdf_path: Optional[str] = None,
) -> int:
    """Create a new report record. Returns the report ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO reports 
               (client_id, risk_score, executive_summary, raw_scan, risk_assessment, remediation_plan, pdf_path) 
               VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7) 
               RETURNING id""",
            client_id, risk_score, executive_summary,
            json.dumps(raw_scan) if raw_scan else None,
            json.dumps(risk_assessment) if risk_assessment else None,
            json.dumps(remediation_plan) if remediation_plan else None,
            pdf_path,
        )
        return row["id"] if row else 0


async def get_report_by_id(report_id: int) -> Optional[Dict[str, Any]]:
    """Get report record by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM reports WHERE id = $1", report_id)
        if row:
            return {"id": row["id"], "client_id": row["client_id"], "risk_score": row["risk_score"],
                    "executive_summary": row["executive_summary"], "raw_scan": row["raw_scan"],
                    "risk_assessment": row["risk_assessment"], "remediation_plan": row["remediation_plan"],
                    "pdf_path": row["pdf_path"], "created_at": row["created_at"]}
        return None


async def list_reports_by_client(client_id: int) -> List[Dict[str, Any]]:
    """List all reports for a client."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM reports WHERE client_id = $1 ORDER BY created_at DESC", client_id,
        )
        return [{"id": row["id"], "risk_score": row["risk_score"], "executive_summary": row["executive_summary"],
                 "created_at": row["created_at"]} for row in rows]


async def get_latest_report(client_id: int) -> Optional[Dict[str, Any]]:
    """Get the latest report for a client."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM reports WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1",
            client_id,
        )
        if row:
            return {"id": row["id"], "risk_score": row["risk_score"], "executive_summary": row["executive_summary"],
                    "raw_scan": row["raw_scan"], "risk_assessment": row["risk_assessment"],
                    "created_at": row["created_at"]}
        return None


async def create_lead_task(domain: str, email: str, name: str) -> int:
    """Create a lead task in the DB. Returns the task ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO lead_tasks (domain, email, name, status) VALUES ($1, $2, $3, 'pending') RETURNING id",
            domain, email, name,
        )
        return row["id"] if row else 0


async def get_lead_task(task_id: int) -> Optional[Dict[str, Any]]:
    """Get a lead task by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM lead_tasks WHERE id = $1", task_id)
        if row:
            return {"id": row["id"], "domain": row["domain"], "email": row["email"],
                    "name": row["name"], "status": row["status"]}
        return None


async def mark_lead_hot(task_id: int, email: str, name: str) -> None:
    """Mark a lead as hot (vulnerable) in the DB."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET status = 'hot', email = $1, name = $2 WHERE id = $3",
            email, name, task_id,
        )


async def get_hot_leads(limit: int = 10) -> List[Dict[str, Any]]:
    """Get hot leads (vulnerable) from the DB, limited by quantity."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM lead_tasks WHERE status = 'hot' ORDER BY created_at DESC LIMIT $1", limit,
        )
        return [{"id": row["id"], "domain": row["domain"], "email": row["email"], "name": row["name"]}
                for row in rows]


async def mark_lead_emailed(task_id: int) -> None:
    """Mark a lead as emailed in the DB."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET status = 'emailed' WHERE id = $1", task_id,
        )


async def activate_subscription(client_id: int, plan: str = "monthly") -> None:
    """Activate a subscription for a client."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if subscription already exists
        exists = await conn.fetchrow(
            "SELECT id FROM subscriptions WHERE client_id = $1", client_id,
        )
        if exists:
            await conn.execute(
                "UPDATE subscriptions SET status = 'active', plan = $1 WHERE client_id = $2",
                plan, client_id,
            )
        else:
            await conn.execute(
                "INSERT INTO subscriptions (client_id, plan, status) VALUES ($1, $2, 'active')",
                client_id, plan,
            )


async def is_subscribed(client_id: int) -> bool:
    """True when the client has an ACTIVE subscription (monitoring tier).

    Gates subscriber-only surfaces: the Digital Twin simulation and every
    score that is free-with-monitoring. Cancelled rows never count.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM subscriptions WHERE client_id = $1 AND status = 'active' LIMIT 1",
            client_id,
        )
        return row is not None


async def save_trajectory(client_id: int, payload: Dict[str, Any]) -> int:
    """Persist a Digital Twin trajectory payload for a client."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO trajectories (client_id, payload) VALUES ($1, $2) RETURNING id",
            client_id, json.dumps(payload),
        )
        return row["id"] if row else 0


async def get_latest_trajectory(client_id: int) -> Optional[Dict[str, Any]]:
    """Most recent saved trajectory for a client (subscribers only)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, payload, created_at FROM trajectories "
            "WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1",
            client_id,
        )
        if row:
            payload = row["payload"]
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {}
            return {"id": row["id"], "payload": payload, "created_at": row["created_at"]}
        return None


async def deactivate_subscription(client_id: int) -> None:
    """Deactivate a subscription for a client (mark as cancelled)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE subscriptions SET status = 'cancelled', cancelled_at = NOW() WHERE client_id = $1",
            client_id,
        )


async def link_paypal_subscription(client_id: int, subscription_id: str) -> None:
    """Stores a PayPal subscription id on the client's subscription row.

    Needed for the Native Button flow: the subscription is created in the
    browser against a plan, so PayPal webhooks only carry the subscription id
    ('I-...') - no custom_id. This link is what lets /webhook/paypal resolve
    the client for activation, cancellation, and payment failures.
    Idempotent: re-linking the same pair is a no-op.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchrow(
            "SELECT id FROM subscriptions WHERE client_id = $1", client_id,
        )
        if exists:
            await conn.execute(
                "UPDATE subscriptions SET paypal_subscription_id = $1 WHERE client_id = $2",
                subscription_id, client_id,
            )
        else:
            await conn.execute(
                "INSERT INTO subscriptions (client_id, plan, status, paypal_subscription_id) "
                "VALUES ($1, 'monthly', 'active', $2)",
                client_id, subscription_id,
            )


async def get_client_id_by_subscription(subscription_id: str) -> Optional[int]:
    """Finds the client ID associated with a PayPal Subscription ID ('I-...').

    Returns None when the subscription was never linked (e.g. a webhook for a
    subscription created outside our checkout).
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT client_id FROM subscriptions WHERE paypal_subscription_id = $1",
            subscription_id,
        )
        return row["client_id"] if row else None


async def save_coupon(client_id: int, stripe_coupon_id: str, percent_off: int = 20,
                      duration: str = "repeating", duration_in_months: int = 3) -> None:
    """Save a coupon code for a client (win-back)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if coupon already exists
        exists = await conn.fetchrow(
            "SELECT id FROM coupons WHERE client_id = $1", client_id,
        )
        if exists:
            await conn.execute(
                "UPDATE coupons SET stripe_coupon_id = $1, percent_off = $2, duration = $3, "
                "duration_in_months = $4, created_at = NOW() WHERE client_id = $5",
                stripe_coupon_id, percent_off, duration, duration_in_months, client_id,
            )
        else:
            await conn.execute(
                "INSERT INTO coupons (client_id, stripe_coupon_id, percent_off, duration, duration_in_months) "
                "VALUES ($1, $2, $3, $4, $5)",
                client_id, stripe_coupon_id, percent_off, duration, duration_in_months,
            )


async def has_event_processed(event_id: str) -> bool:
    """Checks if a Stripe event has already been processed."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM stripe_events WHERE event_id = $1", event_id,
        )
        return row is not None


async def mark_event_processed(event_id: str, event_type: str, client_id: int = None) -> None:
    """Marks a Stripe event as processed."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO stripe_events (event_id, event_type, client_id) VALUES ($1, $2, $3) "
            "ON CONFLICT DO NOTHING",
            event_id, event_type, client_id,
        )


async def is_suppressed(email: str) -> bool:
    """Checks if an email is on the suppression list."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM lead_tasks WHERE email = $1 AND status = 'suppressed' LIMIT 1",
            email,
        )
        return row is not None


async def create_referral(referrer_id: int, referred_domain: str) -> int:
    """Creates a new referral record. Returns the referral ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO referrals (referrer_id, referred_domain, created_at) VALUES ($1, $2, NOW()) RETURNING id",
            referrer_id, referred_domain,
        )
        return row["id"] if row else 0


async def get_referral_by_domain(referred_domain: str) -> Optional[Dict[str, Any]]:
    """Gets the referral record for a domain."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM referrals WHERE referred_domain = $1", referred_domain,
        )
        if row:
            return {"id": row["id"], "referrer_id": row["referrer_id"],
                    "referred_domain": row["referred_domain"], "created_at": row["created_at"]}
        return None


async def apply_referral_discount(referral_id: int, client_id: int) -> int:
    """Applies a 1-month free (100% off) discount to the referred client. Returns the coupon ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO coupons (client_id, percent_off, duration, duration_in_months, max_redemptions, metadata) "
            "VALUES ($1, 100, 'once', 1, 1, $2::jsonb) RETURNING id",
            client_id, json.dumps({"referral_id": referral_id}),
        )
        return row["id"] if row else 0


async def mark_stage_sent(lead_id: int, stage: str) -> None:
    """Marks a follow-up stage as sent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO lead_stages (lead_id, stage, sent_at) VALUES ($1, $2, NOW()) "
            "ON CONFLICT (lead_id, stage) DO NOTHING",
            lead_id, stage,
        )


async def has_stage_sent(lead_id: int, stage: str) -> bool:
    """Checks if a stage has already been sent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM lead_stages WHERE lead_id = $1 AND stage = $2", lead_id, stage,
        )
        return row is not None


async def suppress_lead(lead_id: int, reason: str = "unsubscribed") -> None:
    """Suppresses a lead from all future sends."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET status = 'suppressed', "
            "metadata = jsonb_set(metadata, '{reason}', to_jsonb($1::text)) WHERE id = $2",
            reason, lead_id,
        )


async def get_inbound_leads(limit: int = 20) -> List[Dict[str, Any]]:
    """Gets leads that have opted-in (scan completed) and are not suppressed."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM lead_tasks WHERE status IN ('completed', 'hot') "
            "AND email IS NOT NULL AND email <> '' "
            "ORDER BY updated_at ASC LIMIT $1", limit,
        )
        return [{"id": row["id"], "domain": row["domain"], "email": row["email"],
                 "name": row["name"], "updated_at": row["updated_at"]} for row in rows]


async def get_latest_report_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Get the latest report for a domain (from clients or lead_task scans)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT r.* FROM reports r "
            "WHERE r.client_id IN (SELECT id FROM clients WHERE domain = $1 "
            "UNION SELECT id FROM lead_tasks WHERE domain = $1) "
            "ORDER BY r.created_at DESC LIMIT 1",
            domain,
        )
        if row:
            return {"id": row["id"], "client_id": row["client_id"], "risk_score": row["risk_score"],
                    "executive_summary": row["executive_summary"], "risk_assessment": row["risk_assessment"],
                    "remediation_plan": row["remediation_plan"], "created_at": row["created_at"]}
        return None


async def create_scan_task(domain: str, client_id: Optional[str] = None) -> str:
    """Create a background scan task. Returns the task ID."""
    pool = await get_pool()
    task_id = uuid.uuid4().hex
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO scan_tasks (task_id, domain, client_id, status) VALUES ($1, $2, $3, 'running')",
            task_id, domain, client_id,
        )
    return task_id


async def get_scan_task(task_id: str) -> Optional[Dict[str, Any]]:
    """Get a scan task by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM scan_tasks WHERE task_id = $1", task_id)
        if row:
            return {"task_id": row["task_id"], "domain": row["domain"],
                    "status": row["status"], "error": row["error"],
                    "created_at": row["created_at"], "updated_at": row["updated_at"]}
        return None


async def update_scan_task(task_id: str, status: str, error: Optional[str] = None) -> None:
    """Update a scan task's status (and optional error message)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE scan_tasks SET status = $1, error = $2, updated_at = NOW() WHERE task_id = $3",
            status, error, str(task_id),
        )


async def is_domain_scanning(domain: str) -> bool:
    """Check if a domain already has a running scan."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM scan_tasks WHERE domain = $1 AND status = 'running' LIMIT 1", domain,
        )
        return row is not None


async def get_task_id(domain: str) -> Optional[str]:
    """Get the running scan task ID for a domain, if any."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT task_id FROM scan_tasks WHERE domain = $1 AND status = 'running' "
            "ORDER BY created_at DESC LIMIT 1", domain,
        )
        return row["task_id"] if row else None


async def update_lead_task_status(task_id: int, status: str) -> None:
    """Update a lead task's status (pending/hot/completed/failed/suppressed)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET status = $1, updated_at = NOW() WHERE id = $2",
            status, task_id,
        )


async def set_lead_signals(task_id: int, signals: List[str], harvey_ref: str = "") -> None:
    """Persist Harvey discovery signals + reference on a lead (metadata JSONB)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET metadata = coalesce(metadata, '{}'::jsonb) || "
            "jsonb_build_object('signals', $1::jsonb, 'harvey_ref', to_jsonb($2::text)), "
            "updated_at = NOW() WHERE id = $3",
            json.dumps(signals or []), harvey_ref or "", task_id,
        )


async def get_lead_signals(domain: str) -> List[str]:
    """Latest discovery signals recorded for a domain (empty list if none)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT metadata FROM lead_tasks WHERE domain = $1 "
            "AND metadata ? 'signals' ORDER BY id DESC LIMIT 1",
            domain,
        )
        if not row:
            return []
        meta = row["metadata"]
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except (json.JSONDecodeError, TypeError):
                return []
        signals = (meta or {}).get("signals")
        return signals if isinstance(signals, list) else []


async def get_client(client_id: int) -> Optional[Dict[str, Any]]:
    """Get client record by ID (alias for get_client_by_id)."""
    return await get_client_by_id(client_id)