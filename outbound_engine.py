import asyncio
import os
import random
from datetime import datetime

import httpx

from dotenv import load_dotenv

# Read .env before any module-level os.getenv below. Real environment
# variables always win over the file.
load_dotenv()

from db import (
    get_inbound_leads,
    get_latest_report_by_domain,
    mark_stage_sent,
    has_stage_sent,
)

MAX_EMAILS_PER_DAY = int(os.getenv("MAX_EMAILS_PER_DAY", "20"))
# Voice provider: SendGrid is preferred because its domain auth is CNAME-only
# (the InfinityFree free zone cannot publish Resend's TXT DKIM/SPF records).
# Resend stays as a fallback wherever its TXT records can be published.
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
# Set FROM_EMAIL to a sender on the verified domain.
FROM_EMAIL = os.getenv("FROM_EMAIL", "security@zerodaysentinel.xo.je")


class OutboundEngine:
    def __init__(self):
        self.emails_sent_today = 0
        self.last_reset_date = datetime.now().date()
        self.consecutive_failures = 0
        self.circuit_breaker_active = False
        # Permission-based sending: low daily cap protects domain reputation
        self.MAX_DAILY_LIMIT = MAX_EMAILS_PER_DAY
        # Jitter between sends (tunable for tests / warm-up)
        self.jitter_min = int(os.getenv("JITTER_MIN_SECONDS", "60"))
        self.jitter_max = int(os.getenv("JITTER_MAX_SECONDS", "120"))

    async def _send_email(self, to_email: str, name: str, subject: str, body: str) -> bool:
        """Sends a permission-based email with circuit-breaker logic."""
        if self.circuit_breaker_active:
            print("[CIRCUIT BREAKER] Suppressing email send.")
            return False

        if not SENDGRID_API_KEY and not RESEND_API_KEY:
            print("[WARN] SENDGRID_API_KEY/RESEND_API_KEY not set, email skipped.")
            return False

        html = body.replace("\n", "<br>")
        if SENDGRID_API_KEY:
            # SendGrid v3 mail/send - answers 202 Accepted
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}"}
            payload = {
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": FROM_EMAIL},
                "subject": subject,
                "content": [{"type": "text/html", "value": html}],
            }
        else:
            url = "https://api.resend.com/emails"
            headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
            payload = {
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "html": html,
            }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
            except Exception as e:
                self.consecutive_failures += 1
                print(f"[EMAIL ERROR] {to_email}: {e}")
                return False

            if response.status_code in (200, 202):   # SendGrid answers 202
                self.consecutive_failures = 0  # Reset counter on success
                print(f"[EMAIL SENT] {to_email} | Subject: {subject}")
                return True

            self.consecutive_failures += 1
            print(f"[EMAIL FAIL] {to_email}: {response.status_code}")

            # Circuit Breaker: 3 consecutive failures -> pause 1 hour
            # (stricter threshold protects a new domain's reputation)
            if self.consecutive_failures >= 3:
                self.circuit_breaker_active = True
                print("[ALERT] Circuit Breaker Activated. Pausing outbound for 1 hour.")
                await asyncio.sleep(3600)
                self.circuit_breaker_active = False
                self.consecutive_failures = 0
            return False

    def _reset_daily_counter(self):
        if datetime.now().date() != self.last_reset_date:
            self.emails_sent_today = 0
            self.last_reset_date = datetime.now().date()
            print("[INFO] Daily email counter reset.")

    def _get_follow_up_stage(self, lead: dict) -> str:
        """
        Determines the follow-up stage based on time since last interaction.
        """
        last_updated = lead["updated_at"]
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated)
        days_since = (datetime.now() - last_updated).days

        if days_since < 1:
            return "initial"
        elif days_since < 3:
            return "follow_up_1"
        elif days_since < 7:
            return "follow_up_2"
        else:
            return "win_back"  # 30-day logic handled separately

    async def process_batch(self) -> int:
        """
        Runs one pass over eligible inbound leads (one lead per stage at most).
        Returns the number of emails sent. Extracted from run_loop so it can
        be exercised directly by test_autopilot.py.
        """
        sent = 0

        # 1. Load Inbound Leads (Opted-in via /capture)
        leads = await get_inbound_leads(limit=20)

        for lead in leads:
            if self.emails_sent_today >= self.MAX_DAILY_LIMIT or self.circuit_breaker_active:
                break

            stage = self._get_follow_up_stage(lead)

            # Skip if already sent at this stage
            if await has_stage_sent(lead["id"], stage):
                continue

            domain = lead["domain"]
            email = lead["email"]
            name = lead.get("name", "there")
            # Reports are keyed by client id; resolve via the lead's domain so
            # captured leads always find their generated report.
            report = await get_latest_report_by_domain(domain)

            if not report:
                continue

            # Select template based on stage
            if stage == "initial":
                subject, body = self._build_initial_email(domain, name, report)
            elif stage == "follow_up_1":
                subject, body = self._build_follow_up_1(domain, name, report)
            elif stage == "follow_up_2":
                subject, body = self._build_follow_up_2(domain, name, report)
            else:
                continue  # Win-back handled by separate 30-day cron

            success = await self._send_email(email, name, subject, body)

            if success:
                self.emails_sent_today += 1
                sent += 1
                await mark_stage_sent(lead["id"], stage)

                # Jitter: 60-120s for permission-based sends (less aggressive)
                await asyncio.sleep(random.randint(self.jitter_min, self.jitter_max))

        return sent

    async def run_loop(self):
        """
        Main loop: Follow-up sequences for inbound leads.
        """
        print("[INFO] Inbound Follow-Up Engine Started.")
        while True:
            self._reset_daily_counter()

            if self.emails_sent_today >= self.MAX_DAILY_LIMIT:
                print(f"[INFO] Daily limit ({self.MAX_DAILY_LIMIT}) reached. Sleeping.")
                await asyncio.sleep(3600)
                continue

            await self.process_batch()

            await asyncio.sleep(600)

    def _build_initial_email(self, domain: str, name: str, report: dict) -> tuple:
        """Initial email: The 'Free Scan' delivery."""
        risks = report.get("risk_assessment", [])
        top_risk = risks[0] if risks else {"title": "General Posture", "business_impact": "Standard monitoring recommended"}

        subject = f"Your risk assessment for {domain} is ready"
        body = f"""Hi {name},

You requested a security posture check for {domain}.

**Risk Score:** {report.get('risk_score', 100)}/100
**Top Finding:** {top_risk.get('title')}
**Business Impact:** {top_risk.get('business_impact')}

[View Full Report] (Link to your dashboard)

If you want to keep this monitoring active, we offer a $49/mo service.

Best,
[Your Name]
Zero-Trust Sentinel
"""
        return subject, body

    def _build_follow_up_1(self, domain: str, name: str, report: dict) -> tuple:
        """Follow-up 1: The 'Value Add' (Day 2-3)."""
        subject = f"Quick tip for {domain}'s security posture"
        remediation = report.get('remediation_plan', [{}])[0].get('steps', ['Review your DNS records'])[0]
        body = f"""Hi {name},

Following up on your {domain} assessment.

One quick win: {remediation}

This takes about 5 minutes and can reduce your risk score.

[View Full Report]

Best,
[Your Name]
"""
        return subject, body

    def _build_follow_up_2(self, domain: str, name: str, report: dict) -> tuple:
        """Follow-up 2: The 'Last Call' (Day 5-7)."""
        subject = f"Closing the loop on {domain}"
        body = f"""Hi {name},

I don't want to clutter your inbox.

Your risk assessment for {domain} is still available here: [View Full Report]

If you're interested in automated monitoring, we're offering First 72 Hours Free - Black October Emergency Monitoring, then $49/mo.

If now isn't the right time, no worries. I'll stop emailing you.

Best,
[Your Name]
"""
        return subject, body


    async def resend_health_check(self) -> bool:
        """Startup DKIM/SPF probe: one real email FROM the Voice TO our own
        security address.

        Honest verdict - HOLD here means every follow-up this process attempts
        will bounce, so the Autopilot is not live yet. Returns True on GO.
        """
        probe_to = "security@zerodaysentinel.xo.je"
        provider = ("SendGrid" if SENDGRID_API_KEY
                    else "Resend" if RESEND_API_KEY else None)
        if not provider:
            print("[HEALTHCHECK] HOLD: SENDGRID_API_KEY/RESEND_API_KEY not set - "
                  "DKIM/SPF cannot be verified.")
            return False

        if FROM_EMAIL.split("@")[-1].strip().lower() != "zerodaysentinel.xo.je":
            print(f"[HEALTHCHECK] WARN: FROM_EMAIL={FROM_EMAIL} is not on "
                  f"zerodaysentinel.xo.je - {provider} will reject this sender.")

        ok = await self._send_email(
            probe_to,
            "Autopilot",
            "[Zero-Trust Sentinel] Startup health check",
            "Startup probe from the outbound engine. If you can read this, "
            f"DKIM/SPF wiring for {FROM_EMAIL} is live and the Voice can send.",
        )
        if ok:
            print(f"[HEALTHCHECK] GO: {provider} accepted the test email "
                  f"(from={FROM_EMAIL} -> {probe_to}).")
        else:
            print(f"[HEALTHCHECK] HOLD: {provider} rejected the test email "
                  f"(from={FROM_EMAIL}). Check domain verification, DKIM and "
                  "SPF before opening the Voice.")
        return ok


if __name__ == "__main__":
    engine = OutboundEngine()

    async def _start() -> None:
        # Prove the Voice can send FIRST, and gate lead mail on that proof:
        # without GO every follow-up this process attempts would bounce.
        if not await engine.resend_health_check():
            print("[HEALTHCHECK] HOLD: engine will not mail any lead. Exiting.")
            return
        await engine.run_loop()

    asyncio.run(_start())