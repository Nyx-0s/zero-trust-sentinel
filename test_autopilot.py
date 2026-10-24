#!/usr/bin/env python3
"""Zero-Trust Sentinel - Autopilot End-to-End Pipeline Simulation.

Proves the entire pipeline works WITHOUT live API keys:

    Capture -> Scan -> LLM Analysis -> Report -> Outbound Email
           -> Stripe Payment -> Cancellation -> 30-Day Win-Back

What is mocked:
  * Database   - in-memory SQLite standing in for Neon Postgres
                 (same async function surface as db.py, asyncpg-style pool faked)
  * LLM        - deterministic MockLLM returning fixed JSON for
                 Analyst / Fixer / Editor / Critic prompts (real LangGraph runs)
  * Scanners   - realistic raw_scan JSON for the target domain
  * Email      - httpx.AsyncClient intercepted (SendGrid v3 primary, Resend
                 fallback); payloads normalized and logged to console
  * Stripe     - construct_event / Coupon.create faked; webhook payloads simulated

Run:  python3 test_autopilot.py
Exit: 0 = all stages PASS, 1 = at least one FAIL
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

# --- Environment must be set BEFORE importing api (main.py reads GROQ_API_KEY at import) ---
os.environ.setdefault("GROQ_API_KEY", "gsk_mock_for_simulation")
os.environ.setdefault("SENDGRID_API_KEY", "SG.mock_for_simulation")
os.environ.setdefault("RESEND_API_KEY", "re_mock_for_simulation")
os.environ.setdefault("WIN_BACK_JITTER_SECONDS", "0")  # keep the simulation fast

import httpx  # noqa: E402

# =============================================================================
# Stage report helpers
# =============================================================================

RESULTS: list = []


def stage(number: int, name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((number, name, bool(ok)))
    label = "PASS" if ok else "FAIL"
    suffix = f"  ({detail})" if detail else ""
    print(f"{label}  Stage {number}: {name}{suffix}")


def now_iso() -> str:
    """UTC timestamp in SQLite-friendly format (no microseconds)."""
    return datetime.utcnow().replace(microsecond=0).isoformat(sep=" ")


# =============================================================================
# Mock Database (in-memory SQLite, mirrors db.py's async surface)
# =============================================================================

class MockDatabase:
    """In-memory SQLite implementation of every db.py function the pipeline uses."""

    def __init__(self) -> None:
        # check_same_thread=False: the FastAPI background scan runs on the
        # TestClient event-loop thread while assertions run on the main thread.
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._create_schema()

    # -- schema ------------------------------------------------------------
    def _create_schema(self) -> None:
        c = self.conn
        with self.lock:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    created_at TEXT, last_scan TEXT,
                    status TEXT DEFAULT 'active', name TEXT, email TEXT
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER, risk_score INTEGER DEFAULT 0,
                    executive_summary TEXT, raw_scan TEXT,
                    risk_assessment TEXT, remediation_plan TEXT,
                    pdf_path TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS lead_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT, email TEXT, name TEXT,
                    status TEXT DEFAULT 'pending',
                    updated_at TEXT, metadata TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS lead_stages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lead_id INTEGER NOT NULL, stage TEXT, sent_at TEXT,
                    UNIQUE(lead_id, stage)
                );
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER, stripe_subscription_id TEXT,
                    paypal_subscription_id TEXT UNIQUE,
                    plan TEXT DEFAULT 'monthly', status TEXT DEFAULT 'active',
                    current_period_start TEXT, current_period_end TEXT,
                    cancelled_at TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS coupons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER, stripe_coupon_id TEXT,
                    percent_off INTEGER DEFAULT 0, duration TEXT,
                    duration_in_months INTEGER, redeemed INTEGER DEFAULT 0,
                    created_at TEXT, max_redemptions INTEGER, metadata TEXT
                );
                CREATE TABLE IF NOT EXISTS stripe_events (
                    event_id TEXT PRIMARY KEY, event_type TEXT,
                    client_id INTEGER, processed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS referrals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    referrer_id INTEGER, referred_domain TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS scan_tasks (
                    task_id TEXT PRIMARY KEY, domain TEXT, client_id TEXT,
                    status TEXT DEFAULT 'running', error TEXT,
                    created_at TEXT, updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS trajectories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER, payload TEXT, created_at TEXT
                );
                """
            )
            c.commit()

    async def init_db(self) -> None:
        self._create_schema()

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _row(row) -> dict | None:
        return dict(row) if row else None

    @staticmethod
    def _decode_report(row) -> dict | None:
        if not row:
            return None
        d = dict(row)
        for key in ("raw_scan", "risk_assessment", "remediation_plan"):
            if isinstance(d.get(key), str) and d[key]:
                try:
                    d[key] = json.loads(d[key])
                except json.JSONDecodeError:
                    d[key] = []
        # created_at must be a datetime for the /report freshness check
        if isinstance(d.get("created_at"), str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                pass
        return d

    # -- clients -----------------------------------------------------------
    async def create_client(self, domain: str, email: str = "", name: str = "") -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO clients (domain, email, name, status, created_at, last_scan) "
                "VALUES (?, ?, ?, 'active', ?, ?) "
                "ON CONFLICT(domain) DO NOTHING",
                (domain, email, name, now_iso(), now_iso()),
            )
            self.conn.commit()
            if cur.lastrowid:
                return cur.lastrowid
            row = self.conn.execute("SELECT id FROM clients WHERE domain = ?", (domain,)).fetchone()
            return row["id"]

    async def get_client_by_domain(self, domain: str) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM clients WHERE domain = ?", (domain,)).fetchone())

    async def get_client_by_id(self, client_id: int) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone())

    async def get_client(self, client_id: int) -> dict | None:
        return await self.get_client_by_id(client_id)

    # -- reports -----------------------------------------------------------
    async def create_report(self, client_id: int, risk_score: int, executive_summary: str,
                            raw_scan: dict, risk_assessment: list, remediation_plan: list,
                            pdf_path=None) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO reports (client_id, risk_score, executive_summary, raw_scan, "
                "risk_assessment, remediation_plan, pdf_path, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (client_id, risk_score, executive_summary,
                 json.dumps(raw_scan or {}), json.dumps(risk_assessment or []),
                 json.dumps(remediation_plan or []), pdf_path, now_iso()),
            )
            self.conn.commit()
            return cur.lastrowid

    async def get_report_by_id(self, report_id: int) -> dict | None:
        with self.lock:
            return self._decode_report(self.conn.execute(
                "SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone())

    async def get_latest_report(self, client_id: int) -> dict | None:
        with self.lock:
            return self._decode_report(self.conn.execute(
                "SELECT * FROM reports WHERE client_id = ? ORDER BY created_at DESC LIMIT 1",
                (client_id,)).fetchone())

    async def get_latest_report_by_domain(self, domain: str) -> dict | None:
        with self.lock:
            return self._decode_report(self.conn.execute(
                "SELECT r.* FROM reports r WHERE r.client_id IN "
                "(SELECT id FROM clients WHERE domain = ? "
                "UNION SELECT id FROM lead_tasks WHERE domain = ?) "
                "ORDER BY r.created_at DESC LIMIT 1", (domain, domain)).fetchone())

    async def list_reports_by_client(self, client_id: int) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, risk_score, executive_summary, created_at FROM reports "
                "WHERE client_id = ? ORDER BY created_at DESC", (client_id,)).fetchall()
            return [self._decode_report(r) for r in rows]

    # -- lead tasks --------------------------------------------------------
    async def create_lead_task(self, domain: str, email: str, name: str) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO lead_tasks (domain, email, name, status, updated_at) "
                "VALUES (?, ?, ?, 'pending', ?)", (domain, email, name, now_iso()))
            self.conn.commit()
            return cur.lastrowid

    async def get_lead_task(self, task_id: int) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM lead_tasks WHERE id = ?", (task_id,)).fetchone())

    async def mark_lead_hot(self, task_id: int, email: str, name: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE lead_tasks SET status = 'hot', email = ?, name = ?, updated_at = ? "
                "WHERE id = ?", (email, name, now_iso(), task_id))
            self.conn.commit()

    async def update_lead_task_status(self, task_id: int, status: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE lead_tasks SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_iso(), task_id))
            self.conn.commit()

    async def set_lead_signals(self, task_id: int, signals: list, harvey_ref: str = "") -> None:
        with self.lock:
            row = self.conn.execute(
                "SELECT metadata FROM lead_tasks WHERE id = ?", (task_id,)).fetchone()
            try:
                meta = json.loads(row["metadata"]) if row and row["metadata"] else {}
            except (TypeError, json.JSONDecodeError):
                meta = {}
            meta["signals"] = signals or []
            meta["harvey_ref"] = harvey_ref or ""
            self.conn.execute(
                "UPDATE lead_tasks SET metadata = ?, updated_at = ? WHERE id = ?",
                (json.dumps(meta), now_iso(), task_id))
            self.conn.commit()

    async def get_lead_signals(self, domain: str) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT metadata FROM lead_tasks WHERE domain = ? ORDER BY id DESC",
                (domain,)).fetchall()
        for row in rows:
            try:
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(meta.get("signals"), list) and meta["signals"]:
                return meta["signals"]
        return []

    async def get_hot_leads(self, limit: int = 10) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM lead_tasks WHERE status = 'hot' "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    async def mark_lead_emailed(self, task_id: int) -> None:
        await self.update_lead_task_status(task_id, "emailed")

    async def is_suppressed(self, email: str) -> bool:
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM lead_tasks WHERE email = ? AND status = 'suppressed' LIMIT 1",
                (email,)).fetchone()
            return row is not None

    async def get_inbound_leads(self, limit: int = 20) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, domain, email, name, updated_at FROM lead_tasks "
                "WHERE status IN ('completed', 'hot') AND email IS NOT NULL AND email <> '' "
                "ORDER BY updated_at ASC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # -- stages ------------------------------------------------------------
    async def mark_stage_sent(self, lead_id: int, stage: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO lead_stages (lead_id, stage, sent_at) VALUES (?, ?, ?) "
                "ON CONFLICT(lead_id, stage) DO NOTHING", (lead_id, stage, now_iso()))
            self.conn.commit()

    async def has_stage_sent(self, lead_id: int, stage: str) -> bool:
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM lead_stages WHERE lead_id = ? AND stage = ?",
                (lead_id, stage)).fetchone()
            return row is not None

    # -- subscriptions / coupons ------------------------------------------
    async def activate_subscription(self, client_id: int, plan: str = "monthly") -> None:
        with self.lock:
            exists = self.conn.execute(
                "SELECT id FROM subscriptions WHERE client_id = ?", (client_id,)).fetchone()
            if exists:
                self.conn.execute(
                    "UPDATE subscriptions SET status = 'active', plan = ? WHERE client_id = ?",
                    (plan, client_id))
            else:
                self.conn.execute(
                    "INSERT INTO subscriptions (client_id, plan, status, created_at) "
                    "VALUES (?, ?, 'active', ?)", (client_id, plan, now_iso()))
            self.conn.commit()

    async def deactivate_subscription(self, client_id: int) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE subscriptions SET status = 'cancelled', cancelled_at = ? "
                "WHERE client_id = ?", (now_iso(), client_id))
            self.conn.commit()

    async def link_paypal_subscription(self, client_id: int, subscription_id: str) -> None:
        # Mirrors db.py: store the PayPal subscription id ('I-...') on the
        # client's row so webhooks without custom_id can resolve the client.
        with self.lock:
            exists = self.conn.execute(
                "SELECT id FROM subscriptions WHERE client_id = ?", (client_id,)).fetchone()
            if exists:
                self.conn.execute(
                    "UPDATE subscriptions SET paypal_subscription_id = ? WHERE client_id = ?",
                    (subscription_id, client_id))
            else:
                self.conn.execute(
                    "INSERT INTO subscriptions (client_id, plan, status, paypal_subscription_id, created_at) "
                    "VALUES (?, 'monthly', 'active', ?, ?)",
                    (client_id, subscription_id, now_iso()))
            self.conn.commit()

    async def get_client_id_by_subscription(self, subscription_id: str) -> int | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT client_id FROM subscriptions WHERE paypal_subscription_id = ?",
                (subscription_id,)).fetchone()
            return row["client_id"] if row else None

    def get_subscription(self, client_id: int) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM subscriptions WHERE client_id = ?", (client_id,)).fetchone())

    async def is_subscribed(self, client_id: int) -> bool:
        # Mirrors db.py: only an ACTIVE subscription unlocks the Digital Twin.
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM subscriptions WHERE client_id = ? AND status = 'active' LIMIT 1",
                (client_id,)).fetchone()
            return row is not None

    # -- trajectories (Digital Twin) ---------------------------------------
    async def save_trajectory(self, client_id: int, payload: dict) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO trajectories (client_id, payload, created_at) VALUES (?, ?, ?)",
                (client_id, json.dumps(payload), now_iso()))
            self.conn.commit()
            return cur.lastrowid

    async def get_latest_trajectory(self, client_id: int) -> dict | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT id, payload, created_at FROM trajectories WHERE client_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT 1", (client_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if isinstance(d.get("payload"), str) and d["payload"]:
            try:
                d["payload"] = json.loads(d["payload"])
            except json.JSONDecodeError:
                d["payload"] = {}
        return d

    async def save_coupon(self, client_id: int, stripe_coupon_id: str, percent_off: int = 20,
                          duration: str = "repeating", duration_in_months: int = 3) -> None:
        # Mirrors db.py: one coupon row per client, updated on re-save.
        with self.lock:
            exists = self.conn.execute(
                "SELECT id FROM coupons WHERE client_id = ?", (client_id,)).fetchone()
            if exists:
                self.conn.execute(
                    "UPDATE coupons SET stripe_coupon_id = ?, percent_off = ?, duration = ?, "
                    "duration_in_months = ? WHERE client_id = ?",
                    (stripe_coupon_id, percent_off, duration, duration_in_months, client_id))
            else:
                self.conn.execute(
                    "INSERT INTO coupons (client_id, stripe_coupon_id, percent_off, duration, "
                    "duration_in_months, created_at) VALUES (?,?,?,?,?,?)",
                    (client_id, stripe_coupon_id, percent_off, duration,
                     duration_in_months, now_iso()))
            self.conn.commit()

    # -- stripe events -----------------------------------------------------
    async def has_event_processed(self, event_id: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM stripe_events WHERE event_id = ?", (event_id,)).fetchone() is not None

    async def mark_event_processed(self, event_id: str, event_type: str, client_id=None) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO stripe_events (event_id, event_type, client_id, processed_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(event_id) DO NOTHING",
                (event_id, event_type, client_id, now_iso()))
            self.conn.commit()

    # -- referrals ---------------------------------------------------------
    async def create_referral(self, referrer_id: int, referred_domain: str) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO referrals (referrer_id, referred_domain, created_at) "
                "VALUES (?, ?, ?)", (referrer_id, referred_domain, now_iso()))
            self.conn.commit()
            return cur.lastrowid

    async def get_referral_by_domain(self, referred_domain: str) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM referrals WHERE referred_domain = ?",
                (referred_domain,)).fetchone())

    async def apply_referral_discount(self, referral_id: int, client_id: int) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO coupons (client_id, percent_off, duration, duration_in_months, "
                "max_redemptions, metadata, created_at) VALUES (?, 100, 'once', 1, 1, ?, ?)",
                (client_id, json.dumps({"referral_id": referral_id}), now_iso()))
            self.conn.commit()
            return cur.lastrowid

    # -- scan tasks (for /scan endpoint completeness) ----------------------
    async def create_scan_task(self, domain: str, client_id=None) -> str:
        task_id = f"task_{domain}_{int(time.time() * 1000)}"
        with self.lock:
            self.conn.execute(
                "INSERT INTO scan_tasks (task_id, domain, client_id, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'running', ?, ?)", (task_id, domain, client_id, now_iso(), now_iso()))
            self.conn.commit()
        return task_id

    async def get_scan_task(self, task_id: str) -> dict | None:
        with self.lock:
            return self._row(self.conn.execute(
                "SELECT * FROM scan_tasks WHERE task_id = ?", (task_id,)).fetchone())

    async def update_scan_task(self, task_id: str, status: str, error=None) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE scan_tasks SET status = ?, error = ?, updated_at = ? WHERE task_id = ?",
                (status, error, now_iso(), str(task_id)))
            self.conn.commit()

    async def is_domain_scanning(self, domain: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM scan_tasks WHERE domain = ? AND status = 'running' LIMIT 1",
                (domain,)).fetchone() is not None

    async def get_task_id(self, domain: str) -> str | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT task_id FROM scan_tasks WHERE domain = ? AND status = 'running' "
                "ORDER BY created_at DESC LIMIT 1", (domain,)).fetchone()
            return row["task_id"] if row else None

    # -- asyncpg-compatible pool (used by win_back_cron's raw SQL) ---------
    async def get_pool(self):
        return _FakePool(self)


class _TranslateMixin:
    """Translates the asyncpg-flavoured SQL used by win_back_cron to SQLite."""

    @staticmethod
    def translate(sql: str) -> str:
        sql = re.sub(r"NOW\(\)\s*-\s*INTERVAL\s*'30 days'",
                     "datetime('now','-30 days')", sql, flags=re.IGNORECASE)
        sql = re.sub(r"NOW\(\)", "datetime('now')", sql, flags=re.IGNORECASE)
        sql = re.sub(r"\$\d+", "?", sql)
        return sql


class _FakeAsyncConn(_TranslateMixin):
    def __init__(self, db: MockDatabase):
        self.db = db

    async def fetch(self, sql: str, *params):
        with self.db.lock:
            return self.db.conn.execute(self.translate(sql), params).fetchall()

    async def fetchrow(self, sql: str, *params):
        with self.db.lock:
            return self.db.conn.execute(self.translate(sql), params).fetchone()

    async def execute(self, sql: str, *params):
        with self.db.lock:
            self.db.conn.execute(self.translate(sql), params)
            self.db.conn.commit()
        return "OK"


class _FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, db: MockDatabase):
        self.conn = _FakeAsyncConn(db)

    def acquire(self):
        return _FakeAcquire(self.conn)


# =============================================================================
# Mock LLM (deterministic; the REAL LangGraph graph runs unchanged)
# =============================================================================

ANALYST_RESPONSE = json.dumps({
    "risks": [
        {"id": 1, "title": "Exposed admin panel at admin.stripe.com",
         "severity": "Critical",
         "business_impact": "Attackers could take over customer accounts and trigger fraudulent payouts.",
         "technical_detail": "Admin login page returns HTTP 200 on a public subdomain."},
        {"id": 2, "title": "Missing DMARC record allows domain spoofing",
         "severity": "High",
         "business_impact": "Phishers can send email that appears to come from stripe.com, exposing customers.",
         "technical_detail": "No DMARC TXT record found at _dmarc.stripe.com."},
        {"id": 3, "title": "Server header leaks backend version",
         "severity": "Medium",
         "business_impact": "Attackers can match known CVEs to your exact software versions.",
         "technical_detail": "Response headers expose nginx/1.18.0."},
    ]
})

FIXER_RESPONSE = json.dumps({
    "fixes": [
        {"risk_id": 1, "steps": ["Require VPN or allowlist for /admin", "Enforce MFA for all admin users"],
         "code_snippet": "location /admin { allow 10.0.0.0/8; deny all; }"},
        {"risk_id": 2, "steps": ["Publish a DMARC policy starting at p=none", "Monitor reports, then move to p=quarantine"],
         "code_snippet": "v=DMARC1; p=none; rua=mailto:dmarc@stripe.com"},
        {"risk_id": 3, "steps": ["Set 'server_tokens off;' in nginx", "Remove X-Powered-By headers"],
         "code_snippet": "server_tokens off;"},
    ]
})

EDITOR_RESPONSE = (
    "Observation: stripe.com currently scores 65/100 on external security posture. "
    "Finding: an exposed admin panel presents a critical account-takeover risk, and a missing "
    "DMARC policy leaves the brand open to spoofing. Posture: backend version disclosure narrows "
    "the attack path. Remediation for each item is prioritized in the plan below. "
    "Keep your business safe with Zero-Trust Sentinel."
)

CRITIC_RESPONSE = json.dumps({"errors": [], "suggestions": []})


class MockLLM:
    """Deterministic stand-in for ChatOpenAI (Groq). Dispatches on prompt markers."""

    def __init__(self):
        self.seen_prompts: list = []   # every prompt the real graph sends

    async def ainvoke(self, messages):
        if isinstance(messages, list):
            text = "".join(getattr(m, "content", "") or "" for m in messages)
        else:
            text = str(messages)
        self.seen_prompts.append(text)

        if "Critique this report" in text:
            content = CRITIC_RESPONSE
        elif "150-word executive summary" in text:
            content = EDITOR_RESPONSE
        elif "Senior Security Engineer" in text:
            content = FIXER_RESPONSE
        elif "Identify the top 3 business risks" in text:
            content = ANALYST_RESPONSE
        else:
            content = "{}"
        return SimpleNamespace(content=content)


MOCK_LLM = MockLLM()   # singleton installed into main.llm


# =============================================================================
# Mock Scanner (realistic raw_scan for the target domain)
# =============================================================================

async def mock_run_full_scan(domain: str) -> dict:
    return {
        "domain": domain,
        "subdomains_count": 3,
        "live_hosts": [
            {"url": f"https://www.{domain}", "status_code": 200, "title": "Home", "tech": ["nginx"]},
            {"url": f"https://admin.{domain}", "status_code": 200, "title": "Admin Login", "tech": ["nginx", "php"]},
            {"url": f"https://api.{domain}", "status_code": 401, "title": "API", "tech": ["cloudflare"]},
        ],
        "vulnerabilities": [
            {"template_id": "exposed-admin-panel", "name": "Exposed Admin Panel",
             "severity": "critical", "url": f"https://admin.{domain}",
             "matched_at": f"admin.{domain}",
             "description": "Admin login page reachable from the public internet."},
            {"template_id": "missing-dmarc", "name": "Missing DMARC Record",
             "severity": "high", "url": domain, "matched_at": domain,
             "description": "No DMARC policy; domain can be spoofed."},
        ],
        "tls": {"protocols": ["TLSv1.2", "TLSv1.3"]},
    }


# =============================================================================
# Mock Resend (intercept httpx.AsyncClient; log payloads instead of sending)
# =============================================================================

SENT_EMAILS: list = []


class _FakeHTTPResponse:
    def __init__(self, status_code: int = 200, text: str = '{"id": "mock"}'):
        self.status_code = status_code
        self.text = text

    def json(self):
        import json as _json
        return _json.loads(self.text)


class FakeAsyncClient:
    """Drop-in for httpx.AsyncClient that logs Resend payloads to the console."""

    def __init__(self, *args, **kwargs):
        pass  # accepts timeout=..., auth=..., etc.

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None, **kwargs):
        """PayPal server-to-server lookups (subscription verification)."""
        import json as _json
        if "paypal.com" in url and "/v1/billing/subscriptions/" in url:
            sub_id = url.rsplit("/", 1)[-1]
            if sub_id == "I-BOGUS":        # PayPal does not know this subscription
                return _FakeHTTPResponse(404, _json.dumps({"message": "Subscription not found"}))
            body = {"id": sub_id, "status": "ACTIVE", "plan_id": "PLAN-MONTHLY-49"}
            if sub_id == "I-WRONGPLAN":
                body["plan_id"] = "PLAN-OTHER-9"
            if sub_id == "I-FOREIGN":      # custom_id belongs to a different client
                body["custom_id"] = "999"
            return _FakeHTTPResponse(200, _json.dumps(body))
        raise AssertionError(f"Unexpected outbound GET in simulation: {url}")

    async def post(self, url, headers=None, json=None, **kwargs):
        if "paypal.com" in url:
            import json as _json
            if "/v1/oauth2/token" in url:
                return _FakeHTTPResponse(200, _json.dumps({"access_token": "mock-access-token"}))
            if "/v1/billing/subscriptions" in url:
                return _FakeHTTPResponse(201, _json.dumps({
                    "id": "I-MOCK-SUB-1",
                    "status": "APPROVED",
                    "links": [{"rel": "approve",
                               "href": "https://www.paypal.com/checkoutnow?token=MOCKTOKEN"}],
                }))
            if "/v1/notifications/verify-webhook-signature" in url:
                return _FakeHTTPResponse(200, _json.dumps({"verification_status": "SUCCESS"}))
            raise AssertionError(f"Unexpected PayPal call in simulation: {url}")
        if "api.sendgrid.com" in url:
            # SendGrid v3 payload -> normalize to the {to, subject} shape the
            # stage assertions (and the Resend path) use.
            tos = [t.get("email") for p in (json.get("personalizations") or [])
                   for t in (p.get("to") or [])]
            record = {
                "to": tos,
                "subject": json.get("subject"),
                "from": (json.get("from") or {}).get("email"),
                "provider": "sendgrid",
            }
            SENT_EMAILS.append(record)
            print(f"    [MOCK SENDGRID] to={record['to']} subject={record['subject']!r}")
            return _FakeHTTPResponse(202)   # SendGrid answers 202 Accepted
        if "api.resend.com" in url:
            SENT_EMAILS.append(json)
            print(f"    [MOCK RESEND] to={json.get('to')} subject={json.get('subject')!r}")
            return _FakeHTTPResponse(200)
        raise AssertionError(f"Unexpected outbound POST in simulation: {url}")


# =============================================================================
# Mock Stripe (webhook events + coupon creation)
# =============================================================================

class FakeWebhook:
    pending_event: dict | None = None

    @classmethod
    def construct_event(cls, payload, sig_header, secret, **kwargs):
        if cls.pending_event is None:
            raise ValueError("No pending event set by simulation")
        return cls.pending_event


class FakeCoupon:
    created: list = []

    @classmethod
    def create(cls, **kwargs):
        cls.created.append(kwargs)
        return SimpleNamespace(id=f"cs_mock_coupon_{len(cls.created)}")


fake_stripe = SimpleNamespace(Webhook=FakeWebhook, Coupon=FakeCoupon)


# =============================================================================
# Install all mocks into the real modules
# =============================================================================

def install_mocks(mock_db: MockDatabase) -> None:
    import db
    import api
    import scanners
    import main
    import outbound_engine
    import win_back_cron

    db_functions = [
        name for name in vars(MockDatabase)
        if not name.startswith("_") and name not in ("get_pool",)
    ]

    # 1. db.* (covers api's deferred `from db import ...` inside functions)
    for name in db_functions:
        if hasattr(db, name):
            setattr(db, name, getattr(mock_db, name))
    db.get_pool = mock_db.get_pool

    # 2. api.* / outbound_engine.* / win_back_cron.* (they bound names at import)
    for module in (api, outbound_engine, win_back_cron):
        for name in db_functions:
            if hasattr(module, name):
                setattr(module, name, getattr(mock_db, name))
        if hasattr(module, "get_pool"):
            setattr(module, "get_pool", mock_db.get_pool)

    api.stripe = fake_stripe          # webhook + coupon fakes
    main.llm = MOCK_LLM               # deterministic LLM inside the real graph
    scanners.run_full_scan = mock_run_full_scan
    httpx.AsyncClient = FakeAsyncClient  # shared module: api + outbound both patched


# =============================================================================
# The 14-stage simulation
# =============================================================================

TARGET_DOMAIN = "stripe.com"
LEAD_EMAIL = "ada@lead-example.com"


def run_simulation() -> None:
    mock_db = MockDatabase()
    install_mocks(mock_db)

    import api
    import outbound_engine
    import win_back_cron
    from fastapi.testclient import TestClient

    print("=" * 72)
    print("ZERO-TRUST SENTINEL - AUTOPILOT PIPELINE SIMULATION")
    print(f"Target: {TARGET_DOMAIN}   Lead: {LEAD_EMAIL}")
    print("=" * 72)

    with TestClient(api.app) as client:
        # ---- Stage 1: POST /capture -----------------------------------
        r = client.post("/capture", json={
            "domain": TARGET_DOMAIN, "email": LEAD_EMAIL, "name": "Ada",
        })
        data = r.json()
        scan_id = data.get("scan_id")
        # client_id must come back NOW: the Native PayPal Button needs
        # window.CURRENT_CLIENT_ID before the scan finishes
        stage(1, "POST /capture accepted (returns scan_id + client_id for the Button)",
              data.get("status") == "started" and bool(scan_id)
              and isinstance(data.get("client_id"), int) and data["client_id"] > 0,
              f"status={data.get('status')} scan_id={scan_id} client_id={data.get('client_id')}")

        # ---- Stage 2: background scan completes ------------------------
        status, error = None, None
        deadline = time.time() + 30
        while time.time() < deadline:
            task = client.get(f"/task/{scan_id}").json()
            status, error = task.get("status"), task.get("error")
            if status in ("hot", "completed", "failed"):
                break
            time.sleep(0.2)
        stage(2, "Background scan completed (scanners -> LangGraph -> report)",
              status in ("hot", "completed"), f"status={status} error={error}")

        # ---- Stage 3: risk score < 80 ----------------------------------
        report = client.get(f"/report/{TARGET_DOMAIN}").json()
        risk = report.get("risk_score", 100)
        stage(3, "Public report available with risk_score < 80",
              report.get("status") == "completed" and risk < 80
              and len(report.get("top_risks") or []) >= 3,
              f"score={risk}/100, top_risks={len(report.get('top_risks') or [])}")

        # ---- Stage 4: outbound engine sends Initial Scan email ---------
        engine = outbound_engine.OutboundEngine()
        engine.jitter_min = engine.jitter_max = 0  # no sleeps in simulation
        sent_count = asyncio.run(engine.process_batch())
        matching = [m for m in SENT_EMAILS
                    if LEAD_EMAIL in (m.get("to") or [])
                    and "risk assessment" in (m.get("subject") or "").lower()]
        stage_marked = asyncio.run(mock_db.has_stage_sent(scan_id, "initial"))
        stage(4, "Outbound engine sent 'Initial Scan' email (permission-based)",
              sent_count >= 1 and len(matching) == 1 and stage_marked,
              f"sent={sent_count} "
              f"subject={(matching[0]['subject'] if matching else None)!r} "
              f"stage_recorded={stage_marked}")

        # ---- Stage 5: Stripe checkout webhook --------------------------
        client_row = asyncio.run(mock_db.get_client_by_domain(TARGET_DOMAIN))
        client_id = client_row["id"] if client_row else None
        FakeWebhook.pending_event = {
            "id": "evt_checkout_sim_1",
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"client_id": str(client_id), "plan": "monthly"}}},
        }
        resp = client.post("/webhook/stripe", content=b"{}",
                           headers={"stripe-signature": "t=1,v1=mock"}).json()
        # idempotency replay of the SAME event id
        resp_dup = client.post("/webhook/stripe", content=b"{}",
                               headers={"stripe-signature": "t=1,v1=mock"}).json()
        stage(5, "Stripe checkout webhook received + idempotent on replay",
              resp.get("received") is True and resp_dup.get("duplicate") is True,
              f"first={resp} replay={resp_dup}")

        # ---- Stage 6: subscription activated ---------------------------
        sub = mock_db.get_subscription(client_id)
        stage(6, "activate_subscription recorded (active, monthly)",
              bool(sub) and sub["status"] == "active" and sub["plan"] == "monthly",
              f"subscription={ {k: sub[k] for k in ('status', 'plan')} if sub else None}")

        # ---- Stage 7: cancellation (no immediate email) ----------------
        emails_before = len(SENT_EMAILS)
        FakeWebhook.pending_event = {
            "id": "evt_cancel_sim_1",
            "type": "customer.subscription.deleted",
            "data": {"object": {"metadata": {"client_id": str(client_id)}}},
        }
        resp_cancel = client.post("/webhook/stripe", content=b"{}",
                                  headers={"stripe-signature": "t=1,v1=mock"}).json()
        sub_after = mock_db.get_subscription(client_id)
        no_immediate_email = len(SENT_EMAILS) == emails_before
        stage(7, "Cancellation deactivated subscription, NO immediate email (30-day rule)",
              resp_cancel.get("received") is True
              and sub_after["status"] == "cancelled"
              and sub_after["cancelled_at"] is not None
              and no_immediate_email,
              f"status={sub_after['status']} emails_delta={len(SENT_EMAILS) - emails_before}")

    # ---- Stage 8: 30 days later, win_back_cron sends lifecycle email ---
    fast_forward = (datetime.utcnow() - timedelta(days=31)).replace(microsecond=0).isoformat(sep=" ")
    with mock_db.lock:
        mock_db.conn.execute(
            "UPDATE subscriptions SET cancelled_at = ? WHERE client_id = ?",
            (fast_forward, client_id))
        mock_db.conn.commit()

    asyncio.run(win_back_cron.run_win_back_cron())

    win_backs = [m for m in SENT_EMAILS
                 if LEAD_EMAIL in (m.get("to") or [])
                 and "has stopped" in (m.get("subject") or "").lower()]
    stage_marked_winback = asyncio.run(mock_db.has_stage_sent(client_id, "win_back"))
    stage(8, "win_back_cron sent 'Lifecycle' email after 30-day silence period",
          len(win_backs) == 1 and stage_marked_winback,
          f"emails={len(win_backs)} subject={win_backs[0]['subject'] if win_backs else None!r} "
          f"stage_recorded={stage_marked_winback}")

    # ---- Stage 9: Harvey-enriched capture (signals -> Analyst/Editor/report) ----
    MOCK_LLM.seen_prompts.clear()
    with TestClient(api.app) as client:
        r9 = client.post("/capture", json={
            "domain": "vercel.com",
            "email": "",               # discovery lead: no opt-in email -> never mailed
            "name": "Discovered by Harvey",
            "signals": ["exposed_api", "staging_exposed"],
            "harvey_ref": "hv-test-001",
        }).json()
        scan9 = r9.get("scan_id")
        status9 = None
        deadline = time.time() + 30
        while time.time() < deadline:
            t = client.get(f"/task/{scan9}").json()
            status9 = t.get("status")
            if status9 in ("hot", "completed", "failed"):
                break
            time.sleep(0.2)

        stored = asyncio.run(mock_db.get_lead_signals("vercel.com"))
        rep9 = client.get("/report/vercel.com").json()
        analyst_saw = any("Identify the top 3 business risks" in p and "exposed_api" in p
                          for p in MOCK_LLM.seen_prompts)
        editor_saw = any("150-word executive summary" in p and "exposed_api" in p
                         for p in MOCK_LLM.seen_prompts)
        note_ok = "Given your public API" in (rep9.get("signal_note") or "")
        stage(9, "Harvey capture: signals reach Analyst, Editor, and public report",
              r9.get("status") == "started" and status9 in ("hot", "completed")
              and stored == ["exposed_api", "staging_exposed"]
              and rep9.get("signals") == ["exposed_api", "staging_exposed"]
              and note_ok and analyst_saw and editor_saw,
              f"scan_status={status9} stored={stored} note_ok={note_ok} "
              f"analyst_saw_signals={analyst_saw} editor_saw_signals={editor_saw}")

        # ---- Stage 10: PayPal checkout + webhook lifecycle (global-ready) ----
        os.environ.update({
            "PAYPAL_CLIENT_ID": "mock_client",
            "PAYPAL_SECRET": "mock_secret",
            "PAYPAL_PLAN_ID": "PLAN-MONTHLY-49",
            "PAYPAL_WEBHOOK_ID": "MOCK-WEBHOOK-ID",
            "PAYPAL_SKIP_SIGNATURE_VERIFY": "1",
        })
        cid10 = asyncio.run(mock_db.get_client_by_domain("stripe.com"))["id"]
        checkout = client.post(f"/checkout?client_id={cid10}").json()
        pay_ok = (checkout.get("provider") == "paypal"
                  and "paypal.com/checkoutnow" in (checkout.get("url") or ""))

        activate_evt = {"event_id": "evt_paypal_act_1",
                        "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
                        "resource": {"custom_id": str(cid10)}}
        resp10 = client.post("/webhook/paypal", json=activate_evt).json()
        resp10_dup = client.post("/webhook/paypal", json=activate_evt).json()
        sub10 = mock_db.get_subscription(cid10)   # cancelled in stage 7/8

        cancel_evt = {"event_id": "evt_paypal_cancel_1",
                      "event_type": "BILLING.SUBSCRIPTION.CANCELLED",
                      "resource": {"custom_id": str(cid10)}}
        client.post("/webhook/paypal", json=cancel_evt)
        sub10_after = mock_db.get_subscription(cid10)
        stage(10, "PayPal checkout + webhook lifecycle (activate, idempotent, cancel)",
              pay_ok and resp10.get("received") is True
              and resp10_dup.get("duplicate") is True
              and sub10["status"] == "active"
              and sub10_after["status"] == "cancelled",
              f"provider={checkout.get('provider')} activate={sub10['status']} "
              f"dup={resp10_dup.get('duplicate')} cancel={sub10_after['status']}")

        # ---- Stage 11: Native PayPal Button -> /webhook/paypal-activate ----
        cid11 = asyncio.run(mock_db.get_client_by_domain("vercel.com"))["id"]
        r11 = client.post("/webhook/paypal-activate",
                          json={"subscription_id": "I-NATIVE-1", "client_id": cid11}).json()
        sub11 = mock_db.get_subscription(cid11)
        linked11 = asyncio.run(mock_db.get_client_id_by_subscription("I-NATIVE-1"))
        r11_dup = client.post("/webhook/paypal-activate",
                              json={"subscription_id": "I-NATIVE-1", "client_id": cid11}).json()

        # Attacks: unverifiable / wrong-plan / someone else's subscription
        bogus = client.post("/webhook/paypal-activate",
                            json={"subscription_id": "I-BOGUS", "client_id": cid11})
        wrong_plan = client.post("/webhook/paypal-activate",
                                 json={"subscription_id": "I-WRONGPLAN", "client_id": cid11})
        foreign = client.post("/webhook/paypal-activate",
                              json={"subscription_id": "I-FOREIGN", "client_id": cid11})
        missing = client.post("/webhook/paypal-activate",
                              json={"subscription_id": "", "client_id": cid11})
        sub11_after_attacks = mock_db.get_subscription(cid11)
        stage(11, "Native Button: activate endpoint verifies with PayPal, links, rejects attacks",
              r11.get("status") == "active" and sub11["status"] == "active"
              and linked11 == cid11 and r11_dup.get("status") == "active"
              and bogus.status_code == 402 and wrong_plan.status_code == 402
              and foreign.status_code == 403 and missing.status_code == 400
              and sub11_after_attacks["status"] == "active",
              f"activate={sub11['status']} linked={linked11} "
              f"rejections=404:{bogus.status_code} plan:{wrong_plan.status_code} "
              f"foreign:{foreign.status_code} missing:{missing.status_code}")

        # ---- Stage 12: Native lifecycle - webhooks WITHOUT custom_id ----
        emails_before12 = len(SENT_EMAILS)
        # ACTIVATED carrying only the subscription id -> resolved via the link
        client.post("/webhook/paypal", json={
            "event_id": "evt_native_act_1", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
            "resource": {"id": "I-NATIVE-1"}})
        sub12a = mock_db.get_subscription(cid11)
        # Payment failure must stop the subscription (no more free monitoring)
        client.post("/webhook/paypal", json={
            "event_id": "evt_native_fail_1", "event_type": "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
            "resource": {"id": "I-NATIVE-1"}})
        sub12b = mock_db.get_subscription(cid11)
        # Re-activate, then user cancels in their PayPal wallet (no custom_id)
        client.post("/webhook/paypal", json={
            "event_id": "evt_native_react_1", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
            "resource": {"id": "I-NATIVE-1"}})
        client.post("/webhook/paypal", json={
            "event_id": "evt_native_cancel_1", "event_type": "BILLING.SUBSCRIPTION.CANCELLED",
            "resource": {"id": "I-NATIVE-1"}})
        sub12c = mock_db.get_subscription(cid11)
        no_winback12 = len(SENT_EMAILS) == emails_before12   # 30-day cron owns win-back
        stage(12, "Native lifecycle via subscription-id lookup (activate, payment-failed, cancel)",
              sub12a["status"] == "active" and sub12b["status"] == "cancelled"
              and sub12c["status"] == "cancelled" and no_winback12,
              f"activated={sub12a['status']} payment_failed={sub12b['status']} "
              f"cancelled={sub12c['status']} emails_delta={len(SENT_EMAILS) - emails_before12}")

        # ---- Stage 13: Cockpit - static landing page + CORS + redirect target ----
        page = client.get("/", headers={"Origin": "https://zero-trust-sentinel.vercel.app"})
        html = page.text
        cors_hdr = page.headers.get("access-control-allow-origin")
        # The Native Button's onApprove redirects here - must be live JSON
        dash = client.get(f"/dashboard/{cid11}")
        cockpit_ok = (
            page.status_code == 200
            and "paypal-button-container" in html
            and "/webhook/paypal-activate" in html
            and "P-8E455735W3884671YNLNRSVQ" in html          # native subscribe plan
            and "method: 'POST'" in html                        # /capture is POST-with-JSON
            and cors_hdr in ("*", "https://zero-trust-sentinel.vercel.app")
        )
        dash_ok = dash.status_code == 200 and "risk_score" in dash.json()
        stage(13, "Cockpit: landing page served at /, CORS open for Vercel, dashboard live",
              cockpit_ok and dash_ok,
              f"page={page.status_code} cors={cors_hdr} "
              f"button={'paypal-button-container' in html} dashboard={dash.status_code}")

        # ---- Stage 14: Digital Twin simulation (subscriber-gated) --------
        # cid11's subscription was cancelled in stage 12, so this doubles as
        # the gating check: 403 before activation, trajectory after.
        gated = client.post("/simulate", json={"client_id": str(cid11)})
        asyncio.run(mock_db.activate_subscription(cid11, "monthly"))

        sim = client.post("/simulate", json={
            "client_id": str(cid11), "annual_revenue": 12000000})
        payload = sim.json()
        scenarios = payload.get("scenarios") or {}
        base14, full14 = scenarios.get("baseline") or {}, scenarios.get("full_stack") or {}
        saved14 = asyncio.run(mock_db.get_latest_trajectory(cid11))
        twin_get = client.get(f"/simulate/{cid11}").json()
        # A client with no scan must get the honest error, not a fabricated run
        orphan = client.post("/simulate", json={"client_id": "999999"})
        # Cockpit exposes the section, with the locked (no fabricated numbers) view
        twin_section = "digital-twin" in html and "twin-locked" in html

        stage(14, "Digital Twin: /simulate gated to subscribers, seeded from the real scan, mitigations beat baseline",
              gated.status_code == 403
              and sim.status_code == 200 and payload.get("status") == "completed"
              and base14.get("rounds") == 50
              and (base14.get("breaches") or 0) >= (full14.get("breaches") or 0)
              and base14.get("loss_p50", 0) > full14.get("loss_p50", 0)
              and (base14.get("time_to_detect_hours_p50") or 0) > (full14.get("time_to_detect_hours_p50") or 0)
              and bool(saved14) and twin_get.get("status") == "completed"
              and orphan.status_code == 404 and twin_section,
              f"gated={gated.status_code} sim={sim.status_code} rounds={base14.get('rounds')} "
              f"loss={base14.get('loss_p50')}->{full14.get('loss_p50')} "
              f"detect_h={base14.get('time_to_detect_hours_p50')}->" 
              f"{full14.get('time_to_detect_hours_p50')} saved={bool(saved14)} "
              f"orphan={orphan.status_code} section={twin_section}")


def main() -> int:
    try:
        run_simulation()
    except Exception as exc:  # unexpected crash = pipeline failure
        import traceback
        traceback.print_exc()
        print(f"\nFAIL  Simulation crashed: {type(exc).__name__}: {exc}")
        return 1

    passed = sum(1 for _, _, ok in RESULTS if ok)
    total = len(RESULTS)
    print("=" * 72)
    verdict = "PASS" if passed == total else "FAIL"
    print(f"AUTOPILOT RESULT: {passed}/{total} stages passed - {verdict}")
    print("=" * 72)
    print("\nEmails logged in simulation:")
    for m in SENT_EMAILS:
        print(f"  -> to={m.get('to')} | subject={m.get('subject')!r}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
