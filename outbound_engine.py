import asyncio
import json
import os
import random
import uuid
from datetime import datetime
from typing import Any

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
    has_stage_sent_for_email,
    count_sends_today,
    mailbox_state,
    record_outbound_message,
)
from utils import unsubscribe_token

MAX_EMAILS_PER_DAY = int(os.getenv("MAX_EMAILS_PER_DAY", "20"))
# Voice provider: SendGrid is preferred because its domain auth is CNAME-only
# (the InfinityFree free zone cannot publish Resend's TXT DKIM/SPF records).
# Resend stays as a fallback wherever its TXT records can be published.
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
# Set FROM_EMAIL to a sender on the verified domain.
FROM_EMAIL = os.getenv("FROM_EMAIL", "security@zerodaysentinel.xo.je")
# Replies must land in a monitored inbox. zerodaysentinel.xo.je has no MX, so
# Reply-To points at the operator's real mailbox; a prospect's answer reaches
# a human instead of a black hole.
REPLY_TO = os.getenv("REPLY_TO", "aryan.ahlawat@rftsystems.com")
# When SendGrid Inbound Parse is wired to /webhook/sendgrid/inbound, replies
# must be delivered to the mailbox that Parse is configured for - set
# REPLY_TO_INBOUND to that address. It wins over REPLY_TO whenever set; both
# are re-read at call time so a redeployed env is picked up without code
# changes.
REPLY_TO_INBOUND = os.getenv("REPLY_TO_INBOUND", "").strip()


def _reply_to_address() -> str:
    """Reply-To for outbound mail: REPLY_TO_INBOUND if configured, else REPLY_TO."""
    inbound = (os.getenv("REPLY_TO_INBOUND") or "").strip() or REPLY_TO_INBOUND
    return inbound or REPLY_TO

# Where API links in emails point (reports, unsubscribe). Falls back to SITE_URL.
PUBLIC_API_URL = (os.getenv("PUBLIC_API_URL") or os.getenv("SITE_URL")
                  or "https://zerodaysentinel.xo.je").rstrip("/")
# Set to "1" by cron/CI: process what is due and exit instead of looping,
# so a scheduled job cannot outlive its invocation window.
RUN_ONCE = os.getenv("RUN_ONCE", "").strip().lower() in ("1", "true", "yes")


def _report_items(value):
    """Normalize a report column to a list of findings/steps.

    risk_assessment and remediation_plan are JSONB: depending on how the row
    was read they can arrive as a real list, a JSON string (a connection
    without the jsonb codec), or None. Email building must never crash on
    shape - a string would otherwise be indexed as if it were the list and
    `risks[0]` becomes a single character.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return []


class OutboundEngine:
    def __init__(self):
        self.emails_sent_today = 0
        self.last_reset_date = datetime.now().date()
        self.consecutive_failures = 0
        self.circuit_breaker_active = False
        # Short-lived cron runs seed the daily counter from the DB once.
        self._seeded_daily = False
        # Permission-based sending: low daily cap protects domain reputation
        self.MAX_DAILY_LIMIT = MAX_EMAILS_PER_DAY
        # Jitter between sends (tunable for tests / warm-up)
        self.jitter_min = int(os.getenv("JITTER_MIN_SECONDS", "60"))
        self.jitter_max = int(os.getenv("JITTER_MAX_SECONDS", "120"))

    async def _send_email(self, to_email: str, name: str, subject: str, body: str,
                          lead_id: int = 0, stage: str = "",
                          domain: str = "") -> bool:
        """Sends a permission-based email with circuit-breaker logic.

        Returns True ONLY when the provider accepted the message (SendGrid
        answers 202). Anything else - 4xx, 5xx, transport error - is a
        failure and the caller must not record a stage as sent.

        `lead_id`/`stage`/`domain` identify the send for reply correlation:
        they are written into the payload BEFORE the call, stored only AFTER
        the provider accepts, and let an inbound reply find its lead by
        Message-ID, provider id, or our X-ZS-Message-Key header.
        """
        if self.circuit_breaker_active:
            print("[CIRCUIT BREAKER] Suppressing email send.")
            return False

        if not SENDGRID_API_KEY and not RESEND_API_KEY:
            print("[WARN] SENDGRID_API_KEY/RESEND_API_KEY not set, email skipped.")
            return False

        html = body.replace("\n", "<br>")
        # Correlation ids, built before the request: message_key is ours
        # (stable across providers), message_id is the RFC-style header the
        # receiving client quotes back in In-Reply-To/References.
        message_key = f"zs-{int(lead_id or 0)}-{stage or 'probe'}-{uuid.uuid4().hex[:16]}"
        from_domain = (FROM_EMAIL.split("@")[-1].strip().lower() or "localhost")
        message_id = f"<{message_key}@{from_domain}>"
        reply_to = _reply_to_address()
        if SENDGRID_API_KEY:
            # SendGrid v3 mail/send - answers 202 Accepted
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}"}
            payload = {
                "personalizations": [{
                    "to": [{"email": to_email}],
                    # Custom headers ride along with the message; the inbound
                    # webhook sees them even if the client rewrites Message-ID.
                    "headers": {
                        "X-ZS-Message-Key": message_key,
                        "Message-ID": message_id,
                    },
                    "custom_args": {
                        "zs_message_key": message_key,
                        "zs_lead_id": str(int(lead_id or 0)),
                        "zs_stage": stage or "",
                    },
                }],
                "from": {"email": FROM_EMAIL, "name": "Zero-Trust Sentinel"},
                "reply_to": {"email": reply_to},
                "subject": subject,
                "content": [{"type": "text/html", "value": html}],
                "tracking_settings": {
                    # Opens/clicks are not our opt-out contract; the unsubscribe
                    # link is. Keeping them off also keeps the mail honest.
                    "open_tracking": {"enable": False},
                    "click_tracking": {"enable": False},
                },
                "asm": {"group_id": int(os.getenv("SENDGRID_ASM_GROUP", "0"))}
                if os.getenv("SENDGRID_ASM_GROUP") else {},
            }
            if not payload["asm"]:
                payload.pop("asm")
        else:
            url = "https://api.resend.com/emails"
            headers = {"Authorization": f"Bearer {RESEND_API_KEY}"}
            payload = {
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "html": html,
                "reply_to": reply_to,
                "headers": {
                    "X-ZS-Message-Key": message_key,
                    "Message-ID": message_id,
                },
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
                # Record ONLY now that the provider accepted - and never let a
                # recording problem report an accepted send as failed.
                await self._record_accepted_send(
                    response, message_key, message_id, int(lead_id or 0),
                    stage, subject, to_email, domain)
                return True

            self.consecutive_failures += 1
            # The provider's own reason (Resend's 403 "domain not verified",
            # SendGrid's 403 permissions error, ...) is the only thing that
            # tells an operator what to actually fix, so keep it in the log:
            # truncated, single-line, and never the API key.
            reason = (response.text or "").strip().replace("\n", " ")[:300]
            print(f"[EMAIL FAIL] {to_email}: {response.status_code} {reason}")

            # Circuit Breaker: 3 consecutive failures -> pause 1 hour.
            # NEVER sleep out the pause inside a serverless request
            # (maxDuration 300 would kill the function mid-breaker);
            # flip the flag and let this invocation return - the next
            # cron tick constructs a new engine, and process_batch's
            # early-exit plus the stage gates keep volume zero either way.
            if self.consecutive_failures >= 3:
                self.circuit_breaker_active = True
                print("[ALERT] Circuit Breaker Activated. "
                      "This invocation stops sending (no in-request sleep).")
            return False

    async def _record_accepted_send(self, response: Any, message_key: str,
                                    message_id: str, lead_id: int, stage: str,
                                    subject: str, to_email: str,
                                    domain: str) -> None:
        """Persist one accepted send for later reply correlation.

        Extracts the provider's message id defensively: test fakes and some
        proxies expose no headers at all (AttributeError), SendGrid's 202 body
        can be empty (JSON parse error) - both must not disturb the send that
        already succeeded. The DB write itself is best-effort: a missing table
        or transient pool error warns instead of failing the caller, which is
        about to mark the stage as sent.
        """
        provider_message_id = ""
        try:
            provider_message_id = str(
                response.headers.get("x-message-id") or "").strip()
        except Exception:
            provider_message_id = ""
        if not provider_message_id:
            try:
                data = response.json()
                if isinstance(data, dict):
                    provider_message_id = str(data.get("id") or "").strip()
            except Exception:
                provider_message_id = ""
        try:
            await record_outbound_message(
                message_key=message_key, lead_id=lead_id, mailbox=to_email,
                stage=stage, subject=subject,
                provider_message_id=provider_message_id,
                message_id=message_id, domain=domain, status="accepted")
        except Exception as e:
            print(f"[WARN] outbound correlation not recorded for {to_email}: "
                  f"{type(e).__name__}: {str(e)[:200]}")

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

        # Short-lived callers (the /internal/run-batch cron, RUN_ONCE CI runs)
        # start with an empty in-memory counter; seed it once from today's real
        # sends or the daily cap would grant the full allowance on every call.
        if not self._seeded_daily:
            self.emails_sent_today = await count_sends_today()
            self._seeded_daily = True
            print(f"[INFO] daily cap seeded from DB: "
                  f"{self.emails_sent_today} sent today")

        # 1. Load Inbound Leads (Opted-in via /capture)
        leads = await get_inbound_leads(limit=20)

        for lead in leads:
            if self.emails_sent_today >= self.MAX_DAILY_LIMIT or self.circuit_breaker_active:
                break

            stage = self._get_follow_up_stage(lead)

            # Skip if already sent at this stage
            if await has_stage_sent(lead["id"], stage):
                continue
            # ...or at this stage to this same mailbox via another lead row
            # (discovery re-opening a domain must not double-mail a contact).
            if await has_stage_sent_for_email(lead["email"], stage):
                print(f"[SKIP] {lead['email']} already got '{stage}' on another "
                      f"lead for {lead['domain']}")
                continue
            # Authoritative contact state: a reply or an opt-out recorded by
            # ANY path (inbound webhook, one-click unsubscribe) stops this
            # mailbox server-side right before the send.
            state = await mailbox_state(lead["email"])
            if state:
                print(f"[SKIP] {lead['email']} is '{state}' - follow-ups stopped")
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

            body = self._footer(lead["id"], body)

            success = await self._send_email(email, name, subject, body,
                                             lead_id=lead["id"], stage=stage,
                                             domain=domain)

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

        RUN_ONCE=1 (set by the cron driver) processes exactly one batch and
        returns, so the process never outlives a scheduled invocation.
        """
        print("[INFO] Inbound Follow-Up Engine Started." + (" (single pass)" if RUN_ONCE else ""))
        while True:
            self._reset_daily_counter()

            if self.emails_sent_today >= self.MAX_DAILY_LIMIT:
                print(f"[INFO] Daily limit ({self.MAX_DAILY_LIMIT}) reached. Sleeping.")
                if RUN_ONCE:
                    return
                await asyncio.sleep(3600)
                continue

            n = await self.process_batch()
            print(f"[INFO] batch complete: {n} provider-accepted send(s)")

            if RUN_ONCE:
                return
            await asyncio.sleep(600)

    @staticmethod
    def _footer(lead_id: int, body: str) -> str:
        """Every outbound message carries a working one-click opt-out.

        The link targets the API (the Face is static and cannot serve
        /unsubscribe), and the token is bound to this lead only.
        """
        unsub = f"{PUBLIC_API_URL}/unsubscribe?lead={int(lead_id)}&token={unsubscribe_token(lead_id)}"
        return (f"{body}\n\n---\n"
                f"You are receiving this because your business publishes this "
                f"address and our public-surface assessment applies to your "
                f"domain. Opt out any time (no form, one click): {unsub}\n"
                f"Zero-Trust Sentinel - external attack-surface monitoring")

    def _build_initial_email(self, domain: str, name: str, report: dict) -> tuple:
        """Initial email: the real report, honestly described."""
        risks = [r for r in _report_items(report.get("risk_assessment"))
                 if isinstance(r, dict)]
        top_risk = risks[0] if risks else {"title": "General Posture",
                                           "business_impact": "Standard monitoring recommended"}
        report_url = f"{PUBLIC_API_URL}/report/{domain}"

        subject = f"Public-surface assessment for {domain}"
        body = f"""Hi {name},

We ran a passive, public-surface assessment of {domain} - no login, no
exploitation, only what anyone can observe from the outside.

Risk score: {report.get('risk_score', 100)}/100
Top finding: {top_risk.get('title')}
Business impact: {top_risk.get('business_impact')}

Full report (no gating): {report_url}

If you want this surface watched continuously - new subdomains, TLS drift,
exposed staging - we run that for $49/mo. Happy to walk through the findings
first; just reply to this email.

Best,
Zero-Trust Sentinel
Automated external attack-surface monitoring"""
        return subject, body

    def _build_follow_up_1(self, domain: str, name: str, report: dict) -> tuple:
        """Follow-up 1: The 'Value Add' (Day 2-3)."""
        report_url = f"{PUBLIC_API_URL}/report/{domain}"
        subject = f"Quick win for {domain}"
        plan = [p for p in _report_items(report.get("remediation_plan"))
                if isinstance(p, dict)]
        steps = plan[0].get("steps") if plan else None
        remediation = (steps[0] if steps else "Review your DNS records")
        body = f"""Hi {name},

Following up on the {domain} assessment (report: {report_url}).

One quick win from it: {remediation}

That is about five minutes of work and it moves the score. The rest of the
findings are in the report.

Best,
Zero-Trust Sentinel"""
        return subject, body

    def _build_follow_up_2(self, domain: str, name: str, report: dict) -> tuple:
        """Follow-up 2: The 'Last Call' (Day 5-7). One email, then silence."""
        report_url = f"{PUBLIC_API_URL}/report/{domain}"
        subject = f"Last note on the {domain} assessment"
        body = f"""Hi {name},

Last email from us about {domain} - the assessment stays here either way:
{report_url}

If continuous monitoring matters, reply and we will set up the first 72 hours
free so you can see the feed before any money changes hands ($49/mo after).

If not, no worries: the opt-out link below stops all future email and we
will not write again.

Best,
Zero-Trust Sentinel"""
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
        # RUN_ONCE cron runs skip the probe: the continuous process owns it,
        # and a daily probe from every cron tick would itself be mail volume.
        if not RUN_ONCE and not await engine.resend_health_check():
            print("[HEALTHCHECK] HOLD: engine will not mail any lead. Exiting.")
            return
        await engine.run_loop()

    asyncio.run(_start())