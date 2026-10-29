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
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg

# Database connection pool
_pool: Optional[asyncpg.Pool] = None


async def _configure_connection(conn: asyncpg.Connection) -> None:
    """Per-connection codec setup: JSONB/JSON decode to real dicts/lists.

    asyncpg codecs are registered PER CONNECTION, so this runs as the pool's
    ``init`` callback for every new connection. Registering on a single
    acquired connection (the old code) left every connection the pool created
    later decoding jsonb as a raw string - which is exactly how
    ``report['risk_assessment'][0]`` became ``'['`` and crashed the outbound
    batch on one connection out of ten.
    """
    await conn.set_type_codec(
        "jsonb", encoder=lambda v: v if isinstance(v, str) else json.dumps(v),
        decoder=json.loads, schema="pg_catalog")
    await conn.set_type_codec(
        "json", encoder=lambda v: v if isinstance(v, str) else json.dumps(v),
        decoder=json.loads, schema="pg_catalog")


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
        _pool = await asyncpg.create_pool(database_url, min_size=1, max_size=10,
                                          init=_configure_connection)
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

        # Business intelligence projects + their per-skill outputs
        # (founder-skill integration; additive only - no existing table touched)
        await conn.execute("""CREATE TABLE IF NOT EXISTS business_projects (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            context JSONB NOT NULL DEFAULT '{}'::jsonb,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )""")
        await conn.execute("""CREATE TABLE IF NOT EXISTS business_outputs (
            id SERIAL PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES business_projects(id) ON DELETE CASCADE,
            skill_id VARCHAR(64) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            kind VARCHAR(32),
            content TEXT,
            output JSONB,
            error TEXT,
            meta JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(project_id, skill_id)
        )""")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_business_outputs_project ON business_outputs(project_id)")

        # Paid one-time unlocks ($1.99 score / $9.99 full report).
        # The browser may never grant itself a credit: a row exists only after
        # the API has confirmed with PayPal that this exact order was COMPLETED
        # for the exact amount. Entitlement is read from this table - never
        # from localStorage - and spent exactly once.
        await conn.execute("""CREATE TABLE IF NOT EXISTS unlocks (
            id SERIAL PRIMARY KEY,
            order_id VARCHAR(64) UNIQUE NOT NULL,
            domain VARCHAR(255) NOT NULL,
            kind VARCHAR(16) NOT NULL,
            amount VARCHAR(16) NOT NULL,
            status VARCHAR(16) DEFAULT 'paid',
            consumed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )""")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_unlocks_domain ON unlocks(domain, kind, status)")


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
                    "name": row["name"], "status": row["status"],
                    "updated_at": row["updated_at"]}
        return None


async def get_recent_lead_task(domain: str, within_seconds: int = 21600) -> Optional[Dict[str, Any]]:
    """Newest non-failed lead task for a domain opened inside the window.

    Ingest is idempotent: discovery re-runs the same target list every few
    hours (and the scan button gets clicked twice), and a second task would
    buy a full analysis for a report that already exists - spending the
    Groq daily budget on a duplicate. Failed tasks are excluded so a retry
    still opens a fresh attempt.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM lead_tasks WHERE domain = $1 "
            "AND status IN ('pending', 'running', 'hot', 'cold', 'completed') "
            "ORDER BY id DESC LIMIT 1",
            domain,
        )
        if not row:
            return None
        # The age check happens in Python: SQL clock/interval syntax differs
        # between the production database and the SQLite harness the test
        # suite drives, and this comparison must behave identically in both.
        updated = row["updated_at"]
        if updated is None:
            return None
        now = datetime.now(updated.tzinfo) if updated.tzinfo else datetime.utcnow()
        if (now - updated).total_seconds() > int(within_seconds):
            return None
        return {"id": row["id"], "domain": row["domain"], "email": row["email"],
                "name": row["name"], "status": row["status"],
                "updated_at": row["updated_at"]}


async def claim_lead_task(task_id: int, observed_updated_at: Any) -> bool:
    """Take ownership of a lead scan (lease acquisition).

    CAS on updated_at: exactly one worker can flip the row to 'running', so a
    recovery sweep racing a live scan can never start the same lead twice.
    The observed timestamp comes from get_lead_task; NULL is matched explicitly
    because a comparison against NULL would otherwise never succeed.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE lead_tasks SET status = 'running', updated_at = NOW() "
            "WHERE id = $1 AND status IN ('pending', 'running') "
            "AND (($2::timestamp IS NULL AND updated_at IS NULL) "
            "     OR updated_at = $2::timestamp) "
            "RETURNING id",
            task_id, observed_updated_at,
        )
        return row is not None


async def is_lead_task_stale(task_id: int, pending_after: int = 45,
                             running_after: int = 900) -> bool:
    """True when a lead's scan shows no live worker: still 'pending' with no
    progress, or a 'running' lease that expired (worker died mid-scan).
    Clock comparisons stay in SQL so app and DB never disagree about time.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT ((status = 'pending' "
            "         AND (updated_at IS NULL "
            "              OR updated_at < NOW() - make_interval(secs => $2::int))) "
            "        OR (status = 'running' "
            "            AND (updated_at IS NULL "
            "                 OR updated_at < NOW() - make_interval(secs => $3::int)))) "
            "        AS stale "
            "FROM lead_tasks WHERE id = $1",
            task_id, pending_after, running_after,
        )
        return bool(row["stale"]) if row else False


async def list_recoverable_lead_tasks(pending_after: int = 45,
                                      running_after: int = 900,
                                      limit: int = 5) -> List[Dict[str, Any]]:
    """Lead scans stranded without a live worker (in-process task died with the
    instance, redeploy, or crash). Terminal states are never returned.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, domain, email, name, updated_at FROM lead_tasks "
            "WHERE (status = 'pending' "
            "        AND (updated_at IS NULL "
            "             OR updated_at < NOW() - make_interval(secs => $1::int))) "
            "   OR (status = 'running' "
            "       AND (updated_at IS NULL "
            "            OR updated_at < NOW() - make_interval(secs => $2::int))) "
            "ORDER BY updated_at ASC NULLS FIRST LIMIT $3",
            pending_after, running_after, limit,
        )
        return [{"id": r["id"], "domain": r["domain"], "email": r["email"],
                 "name": r["name"], "updated_at": r["updated_at"]} for r in rows]


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


async def record_unlock(order_id: str, domain: str, kind: str, amount: str) -> bool:
    """Records a PayPal-verified one-time unlock. Returns True when new.

    Idempotent on order_id: a webhook-style retry or a double-click on the
    client can never mint the same paid credit twice.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "INSERT INTO unlocks (order_id, domain, kind, amount) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (order_id) DO NOTHING",
            order_id, domain, kind, amount,
        )
        return result.endswith("1")


async def get_unlock_credits(domain: str) -> Dict[str, int]:
    """Unspent paid credits for a domain, by kind ({'score': n, 'report': m})."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT kind, COUNT(*) AS n FROM unlocks "
            "WHERE domain = $1 AND status = 'paid' GROUP BY kind",
            domain,
        )
        credits = {"score": 0, "report": 0}
        for row in rows:
            if row["kind"] in credits:
                credits[row["kind"]] = int(row["n"])
        return credits


async def consume_unlock(domain: str, kind: str) -> bool:
    """Spends one paid credit for this domain. True only if one was available.

    The SKIP LOCKED subquery makes two concurrent scans for the same domain
    spend two different credits instead of double-spending one.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE unlocks SET status = 'consumed', consumed_at = NOW() "
            "WHERE id = (SELECT id FROM unlocks WHERE domain = $1 AND kind = $2 "
            "            AND status = 'paid' ORDER BY id LIMIT 1 "
            "            FOR UPDATE SKIP LOCKED) "
            "RETURNING id",
            domain, kind,
        )
        return row is not None


async def link_stripe_subscription(client_id: int, subscription_id: str) -> None:
    """Stores a Stripe subscription id on the client's subscription row.

    Stripe invoice events (payment failed / paid) carry the subscription id but
    not our client_id, so this link is what lets /webhook/stripe resolve who the
    invoice belongs to. Idempotent: re-linking the same pair is a no-op.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchrow(
            "SELECT id FROM subscriptions WHERE client_id = $1", client_id,
        )
        if exists:
            await conn.execute(
                "UPDATE subscriptions SET stripe_subscription_id = $1 WHERE client_id = $2",
                subscription_id, client_id,
            )
        else:
            await conn.execute(
                "INSERT INTO subscriptions (client_id, plan, status, stripe_subscription_id) "
                "VALUES ($1, 'monthly', 'active', $2)",
                client_id, subscription_id,
            )


async def get_client_id_by_stripe_subscription(subscription_id: str) -> Optional[int]:
    """Finds the client ID for a Stripe subscription id ('sub_...').

    Returns None when the subscription was never linked (a webhook for a
    subscription created outside our checkout) - callers must then decline the
    event rather than guess at a client.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT client_id FROM subscriptions WHERE stripe_subscription_id = $1",
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


async def count_sends_today() -> int:
    """Messages a provider accepted today (one row per lead stage send).

    The outbound engine's daily counter is per-process; a cron/CI run starts
    with an empty one, so it seeds itself from these records instead of
    silently re-earning the full daily allowance on every invocation.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT count(*) AS n FROM lead_stages "
            "WHERE sent_at >= date_trunc('day', NOW())")
        return int(row["n"]) if row else 0


async def has_stage_sent(lead_id: int, stage: str) -> bool:
    """Checks if a stage has already been sent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM lead_stages WHERE lead_id = $1 AND stage = $2", lead_id, stage,
        )
        return row is not None


async def has_stage_sent_for_email(email: str, stage: str) -> bool:
    """True when this mailbox already received this stage on ANY lead row.

    lead_stages is keyed by lead id, and discovery regularly opens a second
    lead for the same company - so checking the id alone mails the same
    published address twice, which is precisely what a sender must never do
    to its own reputation.
    """
    if not email:
        return False
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM lead_stages s JOIN lead_tasks t ON t.id = s.lead_id "
            "WHERE lower(t.email) = lower($1) AND s.stage = $2 LIMIT 1",
            email, stage,
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


async def update_lead_task_metadata(task_id: int, patch: Dict[str, Any]) -> None:
    """Shallow-merge a patch into lead_tasks.metadata (Postgres JSONB ||).

    Failed leads store their real error here: status='failed' on its own says
    nothing about *why*, and there is no error column to use instead.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET metadata = coalesce(metadata, '{}'::jsonb) || $1::jsonb, "
            "updated_at = NOW() WHERE id = $2",
            json.dumps(patch or {}), task_id,
        )


async def set_lead_signals(task_id: int, signals: List[str], harvey_ref: str = "",
                           evidence: Optional[Dict[str, Any]] = None) -> None:
    """Persist discovery signals + reference + evidence URLs on a lead.

    evidence is the hunter's proof (which URL showed what) - the qualification
    trail a report or a reply can always be checked against.
    """
    patch: Dict[str, Any] = {"signals": signals or [], "harvey_ref": harvey_ref or ""}
    if evidence:
        # Keep it bounded: a homepage excerpt is useful evidence, a full page
        # is not, and metadata is read by every dashboard query.
        slim = {k: (v[:3000] if isinstance(v, str) else v)
                for k, v in evidence.items()
                if k in ("homepage_status", "homepage_text", "exposed_api_url",
                         "staging_host", "staging_status", "security_page",
                         "last_modified", "contact_source")}
        patch["evidence"] = slim
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE lead_tasks SET metadata = coalesce(metadata, '{}'::jsonb) || $1::jsonb, "
            "updated_at = NOW() WHERE id = $2",
            json.dumps(patch), task_id,
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


# ---------------------------------------------------------------------------
# Business intelligence (founder-skill integration)
# ---------------------------------------------------------------------------

async def create_business_project(name: str,
                                  context: Optional[Dict[str, Any]] = None) -> int:
    """Create a business-analysis project. Returns the project id."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO business_projects (name, context) "
            "VALUES ($1, $2) RETURNING id",
            name, json.dumps(context or {}),
        )
        return row["id"] if row else 0


async def list_business_projects() -> List[Dict[str, Any]]:
    """All business projects with a status count per project."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT p.id, p.name, p.status, p.created_at, p.updated_at,
                      count(o.id) FILTER (WHERE o.status = 'complete') AS complete,
                      count(o.id) FILTER (WHERE o.status = 'failed') AS failed,
                      count(o.id) AS outputs
               FROM business_projects p
               LEFT JOIN business_outputs o ON o.project_id = p.id
               GROUP BY p.id ORDER BY p.id DESC"""
        )
        return [dict(r) for r in rows]


async def get_business_project(project_id: int) -> Optional[Dict[str, Any]]:
    """One business project with its context."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name, context, status, created_at, updated_at "
            "FROM business_projects WHERE id = $1", project_id)
        return dict(row) if row else None


async def update_business_project_context(project_id: int,
                                          context: Dict[str, Any]) -> None:
    """Replace a project's business context."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE business_projects SET context = $1, updated_at = NOW() "
            "WHERE id = $2", json.dumps(context or {}), project_id)


async def save_business_output(project_id: int, skill_id: str, status: str,
                               kind: str = "", content: str = "",
                               output: Optional[Dict[str, Any]] = None,
                               error: Optional[str] = None,
                               meta: Optional[Dict[str, Any]] = None) -> None:
    """Upsert the latest result of one skill for one project."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO business_outputs
                   (project_id, skill_id, status, kind, content, output, error, meta)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (project_id, skill_id) DO UPDATE SET
                   status = EXCLUDED.status,
                   kind = EXCLUDED.kind,
                   content = EXCLUDED.content,
                   output = EXCLUDED.output,
                   error = EXCLUDED.error,
                   meta = EXCLUDED.meta,
                   updated_at = NOW()""",
            project_id, skill_id, status, kind, content,
            json.dumps(output or {}), error, json.dumps(meta or {}),
        )


async def get_business_outputs(project_id: int) -> List[Dict[str, Any]]:
    """Every recorded skill output for a project (status/error, no bulk body)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT skill_id, status, kind, error, meta, updated_at,
                      length(content) AS content_length
               FROM business_outputs WHERE project_id = $1 ORDER BY id""",
            project_id)
        return [dict(r) for r in rows]


async def get_business_output(project_id: int,
                              skill_id: str) -> Optional[Dict[str, Any]]:
    """One skill's full output document."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT project_id, skill_id, status, kind, content, output, "
            "error, meta, created_at, updated_at FROM business_outputs "
            "WHERE project_id = $1 AND skill_id = $2", project_id, skill_id)
        return dict(row) if row else None