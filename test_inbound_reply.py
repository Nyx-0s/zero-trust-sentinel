#!/usr/bin/env python3
"""Focused regression tests for inbound reply automation and outbound correlation.

No network, no real email, no live database. db functions and httpx are
faked the same way test_autopilot.py fakes them.

Covers the Phase 3/4 contract:
  * outbound correlation recorded only after provider acceptance
  * inbound webhook parsing (SendGrid Inbound Parse shapes)
  * webhook idempotency (same external_id -> one logical reply)
  * reply matching strength order
  * unsubscribe / bounce -> mailbox-wide suppression
  * duplicate mailbox stage protection
  * follow-up cancellation after a reply
  * INTERESTED / QUESTION handoffs
  * malformed payload, unknown sender, unmatched reply
  * email header injection sanitization
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

# Keep secrets out of the real .env for every test in this file.
os.environ.setdefault("GROQ_API_KEY", "gsk_mock_for_inbound_tests")
os.environ.setdefault("SENDGRID_API_KEY", "SG.mock_for_inbound_tests")
os.environ.pop("INBOUND_WEBHOOK_SECRET", None)
os.environ.pop("REPLY_LLM_CLASSIFY", None)

REPO = os.path.dirname(os.path.abspath(__file__))
if REPO not in sys.path:
    sys.path.insert(0, REPO)


# ---------------------------------------------------------------------------
# Fake DB layer - in-memory, mirrors the contracts the pipeline relies on.
# ---------------------------------------------------------------------------

class FakeDB:
    def __init__(self) -> None:
        self.outbound: Dict[str, Dict[str, Any]] = {}
        self.inbound: Dict[str, Dict[str, Any]] = {}
        self.leads: Dict[int, Dict[str, Any]] = {}
        self.handoffs: List[Dict[str, Any]] = []
        self.stages: Dict[tuple, str] = {}
        self._next_lead = 1
        self._next_inbound = 1
        self._next_handoff = 1
        self.suppressed_calls: List[tuple] = []
        self.replied_calls: List[tuple] = []

    def add_lead(self, email: str, domain: str = "example.com",
                 name: str = "Ada", status: str = "completed") -> int:
        from datetime import datetime
        lead_id = self._next_lead
        self._next_lead += 1
        self.leads[lead_id] = {
            "id": lead_id, "email": email, "domain": domain, "name": name,
            "status": status, "updated_at": datetime.now(),
            "metadata": {},
        }
        return lead_id

    def add_outbound(self, message_key: str, lead_id: int, mailbox: str,
                     stage: str = "initial", subject: str = "hi",
                     provider_message_id: str = "", message_id: str = "",
                     domain: str = "example.com", status: str = "accepted") -> None:
        self.outbound[message_key] = {
            "message_key": message_key, "lead_id": lead_id,
            "mailbox": mailbox.lower(), "stage": stage, "subject": subject,
            "provider_message_id": provider_message_id, "message_id": message_id,
            "domain": domain, "status": status,
        }


FAKE = FakeDB()


async def fake_record_outbound_message(message_key: str, lead_id: int,
                                       mailbox: str, stage: str = "",
                                       subject: str = "",
                                       provider_message_id: str = "",
                                       message_id: str = "", domain: str = "",
                                       status: str = "accepted") -> None:
    FAKE.add_outbound(message_key, int(lead_id), mailbox, stage, subject,
                      provider_message_id, message_id, domain, status)


async def fake_get_outbound_by_message_key(key: str):
    return FAKE.outbound.get(key)


async def fake_get_outbound_by_provider_id(pid: str):
    for row in FAKE.outbound.values():
        if row.get("provider_message_id") == pid:
            return row
    return None


async def fake_get_outbound_by_message_id(mid: str):
    for row in FAKE.outbound.values():
        if row.get("message_id") == mid:
            return row
    return None


async def fake_get_outbound_recipient_mailbox(mailbox: str):
    mailbox = (mailbox or "").lower()
    for row in FAKE.outbound.values():
        if row.get("mailbox") == mailbox:
            return row
    return None


async def fake_get_lead_task(lead_id: int):
    return FAKE.leads.get(int(lead_id))


async def fake_get_lead_by_email_strongest(email: str):
    email = (email or "").lower()
    for lead in FAKE.leads.values():
        if (lead.get("email") or "").lower() == email:
            return lead
    return None


async def fake_get_lead_by_domain(domain: str):
    domain = (domain or "").lower()
    for lead in FAKE.leads.values():
        if (lead.get("domain") or "").lower() == domain:
            return lead
    return None


async def fake_get_inbound_by_external_id(ext: str):
    return FAKE.inbound.get(ext)


async def fake_insert_inbound_message(**kwargs) -> int:
    ext = kwargs.get("external_id") or ""
    if ext in FAKE.inbound:
        return FAKE.inbound[ext]["id"]
    row_id = FAKE._next_inbound
    FAKE._next_inbound += 1
    FAKE.inbound[ext] = {"id": row_id, **kwargs}
    return row_id


async def fake_suppress_mailbox(email: str, reason: str = "unsubscribed") -> int:
    FAKE.suppressed_calls.append((email.lower(), reason))
    n = 0
    for lead in FAKE.leads.values():
        if (lead.get("email") or "").lower() == email.lower():
            lead["status"] = "suppressed"
            n += 1
    return n


async def fake_mark_mailbox_replied(email: str, classification: str = "OTHER") -> int:
    FAKE.replied_calls.append((email.lower(), classification))
    n = 0
    for lead in FAKE.leads.values():
        if ((lead.get("email") or "").lower() == email.lower()
                and lead.get("status") in ("completed", "hot", "pending", "running")):
            lead["status"] = "replied"
            n += 1
    return n


async def fake_create_handoff(**kwargs) -> int:
    hid = FAKE._next_handoff
    FAKE._next_handoff += 1
    FAKE.handoffs.append({"id": hid, "status": "open", **kwargs})
    return hid


async def fake_mailbox_state(email: str) -> str:
    email = (email or "").lower()
    statuses = [(l.get("status") or "") for l in FAKE.leads.values()
                if (l.get("email") or "").lower() == email]
    if "suppressed" in statuses:
        return "suppressed"
    if "replied" in statuses:
        return "replied"
    return ""


async def fake_has_stage_sent(lead_id: int, stage: str) -> bool:
    return (int(lead_id), stage) in FAKE.stages


async def fake_has_stage_sent_for_email(email: str, stage: str) -> bool:
    email = (email or "").lower()
    for (lid, stg), _ in FAKE.stages.items():
        if stg != stage:
            continue
        lead = FAKE.leads.get(lid)
        if lead and (lead.get("email") or "").lower() == email:
            return True
    return False


async def fake_mark_stage_sent(lead_id: int, stage: str) -> None:
    FAKE.stages[(int(lead_id), stage)] = "sent"


async def fake_count_sends_today() -> int:
    return len(FAKE.stages)


async def fake_get_inbound_leads(limit: int = 20):
    """Mirror of the fixed SQL contract: exclude suppressed/replied mailboxes."""
    out = []
    for lead in FAKE.leads.values():
        if lead.get("status") not in ("completed", "hot"):
            continue
        if not lead.get("email"):
            continue
        if await fake_mailbox_state(lead["email"]):
            continue
        # any matched inbound from this mailbox also stops it
        stopped = any(
            (row.get("from_address") or "").lower() == lead["email"].lower()
            and row.get("match_method") != "unmatched"
            for row in FAKE.inbound.values()
        )
        if stopped:
            continue
        out.append(lead)
        if len(out) >= limit:
            break
    return out


async def fake_get_latest_report_by_domain(domain: str):
    return {"risk_score": 42, "risk_assessment": [{"title": "T", "business_impact": "B"}],
            "remediation_plan": [{"steps": ["fix it"]}]}


class _FakeHTTPResponse:
    def __init__(self, status_code: int = 202, headers: Optional[dict] = None,
                 text: str = "", json_body: Any = None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_body

    def json(self):
        if self._json is None:
            raise ValueError("no body")
        return self._json


class FakeAsyncClient:
    """Stands in for httpx.AsyncClient - never hits the network."""

    responses: List[_FakeHTTPResponse] = []
    last_payload: Dict[str, Any] = {}
    last_url: str = ""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, headers=None, json=None, **kwargs):
        FakeAsyncClient.last_url = url
        FakeAsyncClient.last_payload = json or {}
        if not FakeAsyncClient.responses:
            return _FakeHTTPResponse(202, headers={"x-message-id": "sg-test-1"})
        return FakeAsyncClient.responses.pop(0)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class InboundTestCase(unittest.TestCase):
    def setUp(self):
        global FAKE
        FAKE = FakeDB()
        # Rebind every fake to the fresh store.
        import db as db_mod
        import inbound
        import outbound_engine

        self._db_patch = {
            "record_outbound_message": fake_record_outbound_message,
            "get_outbound_by_message_key": fake_get_outbound_by_message_key,
            "get_outbound_by_provider_id": fake_get_outbound_by_provider_id,
            "get_outbound_by_message_id": fake_get_outbound_by_message_id,
            "get_outbound_recipient_mailbox": fake_get_outbound_recipient_mailbox,
            "get_lead_task": fake_get_lead_task,
            "get_lead_by_email_strongest": fake_get_lead_by_email_strongest,
            "get_lead_by_domain": fake_get_lead_by_domain,
            "get_inbound_by_external_id": fake_get_inbound_by_external_id,
            "insert_inbound_message": fake_insert_inbound_message,
            "suppress_mailbox": fake_suppress_mailbox,
            "mark_mailbox_replied": fake_mark_mailbox_replied,
            "create_handoff": fake_create_handoff,
            "mailbox_state": fake_mailbox_state,
            "has_stage_sent": fake_has_stage_sent,
            "has_stage_sent_for_email": fake_has_stage_sent_for_email,
            "mark_stage_sent": fake_mark_stage_sent,
            "count_sends_today": fake_count_sends_today,
            "get_inbound_leads": fake_get_inbound_leads,
            "get_latest_report_by_domain": fake_get_latest_report_by_domain,
        }
        self._originals = {}
        for name, fn in self._db_patch.items():
            self._originals[name] = getattr(db_mod, name, None)
            setattr(db_mod, name, fn)
            # Modules that imported by name need the same binding.
            if hasattr(inbound, name):
                setattr(inbound, name, fn)
            if hasattr(outbound_engine, name):
                setattr(outbound_engine, name, fn)

        # httpx fakes for the outbound engine.
        self._orig_async_client = outbound_engine.httpx.AsyncClient
        outbound_engine.httpx.AsyncClient = FakeAsyncClient
        FakeAsyncClient.responses = []
        FakeAsyncClient.last_payload = {}
        FakeAsyncClient.last_url = ""

    def tearDown(self):
        import db as db_mod
        import inbound
        import outbound_engine
        for name, fn in self._originals.items():
            if fn is not None:
                setattr(db_mod, name, fn)
                if hasattr(inbound, name):
                    setattr(inbound, name, fn)
                if hasattr(outbound_engine, name):
                    setattr(outbound_engine, name, fn)
        outbound_engine.httpx.AsyncClient = self._orig_async_client


# ---------------------------------------------------------------------------
# 1. Outbound correlation
# ---------------------------------------------------------------------------

class OutboundCorrelationTests(InboundTestCase):
    def test_accepted_send_records_outbound_message(self):
        import outbound_engine
        lead_id = FAKE.add_lead("ada@example.com")
        engine = outbound_engine.OutboundEngine()
        engine.jitter_min = 0
        engine.jitter_max = 0
        engine.MAX_DAILY_LIMIT = 10
        engine._seeded_daily = True
        engine.emails_sent_today = 0

        sent = run(engine.process_batch())
        self.assertEqual(sent, 1)
        self.assertEqual(len(FAKE.outbound), 1)
        row = next(iter(FAKE.outbound.values()))
        self.assertEqual(row["lead_id"], lead_id)
        self.assertEqual(row["mailbox"], "ada@example.com")
        # Fresh lead (updated_at=now) is always the initial stage.
        self.assertEqual(row["stage"], "initial")
        self.assertEqual(row["status"], "accepted")
        self.assertTrue(row["message_key"].startswith("zs-"))
        self.assertIn("Message-ID", FakeAsyncClient.last_payload
                      .get("personalizations", [{}])[0].get("headers", {}))
        self.assertIn("X-ZS-Message-Key", FakeAsyncClient.last_payload
                      .get("personalizations", [{}])[0].get("headers", {}))

    def test_rejected_send_records_nothing_and_does_not_mark_stage(self):
        import outbound_engine
        FAKE.add_lead("ada@example.com")
        engine = outbound_engine.OutboundEngine()
        engine.jitter_min = 0
        engine.jitter_max = 0
        engine._seeded_daily = True
        engine.emails_sent_today = 0
        FakeAsyncClient.responses = [_FakeHTTPResponse(403, text="forbidden")]

        sent = run(engine.process_batch())
        self.assertEqual(sent, 0)
        self.assertEqual(len(FAKE.outbound), 0)
        self.assertEqual(len(FAKE.stages), 0)

    def test_duplicate_mailbox_same_stage_not_mailed_twice(self):
        import outbound_engine
        # Two lead rows, same mailbox - classic discovery re-open.
        FAKE.add_lead("ada@example.com", domain="a.example")
        FAKE.add_lead("ada@example.com", domain="b.example")
        engine = outbound_engine.OutboundEngine()
        engine.jitter_min = 0
        engine.jitter_max = 0
        engine._seeded_daily = True
        engine.emails_sent_today = 0

        sent = run(engine.process_batch())
        self.assertEqual(sent, 1)
        # Second row must have been skipped by has_stage_sent_for_email.
        self.assertEqual(len(FAKE.outbound), 1)

    def test_mailbox_state_suppressed_blocks_send(self):
        import outbound_engine
        lead_id = FAKE.add_lead("ada@example.com", status="suppressed")
        engine = outbound_engine.OutboundEngine()
        engine._seeded_daily = True
        engine.emails_sent_today = 0
        # get_inbound_leads already filters, but process_batch must also gate.
        leads = run(fake_get_inbound_leads())
        self.assertEqual(leads, [])
        self.assertEqual(run(engine.process_batch()), 0)


# ---------------------------------------------------------------------------
# 2-3. Webhook parse + idempotency
# ---------------------------------------------------------------------------

class WebhookParseTests(InboundTestCase):
    def _form_payload(self, **fields) -> bytes:
        return urlencode(fields).encode("utf-8")

    def test_parse_urlencoded_sendgrid_payload(self):
        from inbound import parse_sendgrid_inbound
        raw = self._form_payload(**{
            "token": "abc123",
            "from": "Ada Lovelace <ada@example.com>",
            "to": "replies@zerodaysentinel.xo.je",
            "subject": "Re: Public-surface assessment for example.com",
            "text": "Interested - can we talk pricing?",
            "headers": "Message-ID: <abc@x>\nIn-Reply-To: <zs-1@zerodaysentinel.xo.je>",
        })
        parsed = parse_sendgrid_inbound(raw, "application/x-www-form-urlencoded")
        self.assertEqual(parsed["from_address"], "ada@example.com")
        self.assertEqual(parsed["recipient"], "replies@zerodaysentinel.xo.je")
        self.assertIn("pricing", parsed["body"])
        self.assertEqual(parsed["external_id"], "sg-abc123")
        self.assertEqual(parsed["headers"].get("Message-ID"), "<abc@x>")

    def test_parse_multipart_payload(self):
        from inbound import parse_sendgrid_inbound
        boundary = "----ZsBoundary"
        parts = [
            f"--{boundary}",
            'Content-Disposition: form-data; name="from"',
            "",
            "Bob <bob@corp.example>",
            f"--{boundary}",
            'Content-Disposition: form-data; name="subject"',
            "",
            "Question about the report",
            f"--{boundary}",
            'Content-Disposition: form-data; name="text"',
            "",
            "How does continuous monitoring work?",
            f"--{boundary}--",
            "",
        ]
        raw = "\r\n".join(parts).encode("utf-8")
        parsed = parse_sendgrid_inbound(
            raw, f"multipart/form-data; boundary={boundary}")
        self.assertEqual(parsed["from_address"], "bob@corp.example")
        self.assertEqual(parsed["subject"], "Question about the report")
        self.assertIn("monitoring", parsed["body"])

    def test_webhook_idempotency_same_external_id(self):
        from inbound import process_inbound
        lead_id = FAKE.add_lead("ada@example.com")
        FAKE.add_outbound("zs-1-initial-x", lead_id, "ada@example.com",
                          message_id="<zs-1-initial-x@zerodaysentinel.xo.je>")
        raw_payload = {
            "external_id": "sg-fixed-token",
            "from_address": "ada@example.com",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "Interested",
            "body": "Yes, interested in a demo",
            "headers": {},
        }
        first = run(process_inbound(dict(raw_payload)))
        second = run(process_inbound(dict(raw_payload)))
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["inbound_id"], second["inbound_id"])
        self.assertEqual(len(FAKE.inbound), 1)
        # Side effects ran once: one handoff, one replied mark.
        self.assertEqual(len(FAKE.handoffs), 1)
        self.assertEqual(len(FAKE.replied_calls), 1)

    def test_malformed_payload_is_handled(self):
        from inbound import parse_sendgrid_inbound, process_inbound
        # Completely empty form
        parsed = parse_sendgrid_inbound(b"", "application/x-www-form-urlencoded")
        self.assertEqual(parsed["from_address"], "")
        self.assertTrue(parsed["external_id"])
        # process_inbound must not crash on empty fields
        result = run(process_inbound(parsed))
        self.assertTrue(result["received"])
        self.assertEqual(result["classification"], "OTHER")

    def test_header_injection_in_subject_sanitized_or_stored_raw(self):
        from inbound import parse_sendgrid_inbound
        raw = self._form_payload(**{
            "token": "inj1",
            "from": "evil@example.com",
            "subject": "Hello\r\nBcc: victim@other.com",
            "text": "hi",
        })
        parsed = parse_sendgrid_inbound(raw, "application/x-www-form-urlencoded")
        # urlencode/parse_qs keeps the bytes; we must never re-inject them
        # into SMTP headers. Storing them as data is fine - assert the
        # outbound path never reuses this subject as a header value.
        self.assertIsInstance(parsed["subject"], str)
        # The engine builds subjects from domain templates only, never from
        # inbound subject - so no outbound header can carry the injection.
        import outbound_engine
        engine = outbound_engine.OutboundEngine()
        subject, _ = engine._build_initial_email("example.com", "Ada", {
            "risk_score": 1, "risk_assessment": [], "remediation_plan": []})
        self.assertNotIn("\r\n", subject)
        self.assertNotIn("Bcc:", subject)


# ---------------------------------------------------------------------------
# 4. Reply matching
# ---------------------------------------------------------------------------

class ReplyMatchingTests(InboundTestCase):
    def test_match_by_message_key_header(self):
        from inbound import match_reply
        lead_id = FAKE.add_lead("ada@example.com")
        FAKE.add_outbound("zs-9-initial-abc", lead_id, "ada@example.com")
        parsed = {
            "from_address": "ada@example.com",
            "headers": {"X-ZS-Message-Key": "zs-9-initial-abc"},
        }
        result = run(match_reply(parsed))
        self.assertEqual(result["method"], "message_key")
        self.assertEqual(result["lead"]["id"], lead_id)

    def test_match_by_in_reply_to_message_id(self):
        from inbound import match_reply
        lead_id = FAKE.add_lead("ada@example.com")
        mid = "<zs-2-follow_up_1-xyz@zerodaysentinel.xo.je>"
        FAKE.add_outbound("zs-2-follow_up_1-xyz", lead_id, "ada@example.com",
                          message_id=mid)
        parsed = {
            # Different From than the lead mailbox (assistant replies from
            # another address) - headers must still win.
            "from_address": "assistant@example.com",
            "headers": {"In-Reply-To": mid},
        }
        result = run(match_reply(parsed))
        self.assertEqual(result["method"], "in_reply_to")
        self.assertEqual(result["lead"]["id"], lead_id)

    def test_match_by_provider_id(self):
        from inbound import match_reply
        lead_id = FAKE.add_lead("ada@example.com")
        FAKE.add_outbound("k1", lead_id, "ada@example.com",
                          provider_message_id="sg.abc999")
        parsed = {
            "from_address": "someone-else@corp.example",
            "headers": {"In-Reply-To": "<sg.abc999@sendgrid.com>"},
        }
        result = run(match_reply(parsed))
        self.assertIn(result["method"], ("provider_id", "in_reply_to", "message_key"))
        self.assertEqual(result["lead"]["id"], lead_id)

    def test_match_by_exact_mailbox(self):
        from inbound import match_reply
        lead_id = FAKE.add_lead("ada@example.com")
        parsed = {"from_address": "ada@example.com", "headers": {}}
        result = run(match_reply(parsed))
        self.assertEqual(result["method"], "from_address")
        self.assertEqual(result["lead"]["id"], lead_id)

    def test_unknown_sender_is_unmatched(self):
        from inbound import match_reply, process_inbound
        parsed = {
            "external_id": "sg-stranger",
            "from_address": "stranger@nowhere.example",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "hi",
            "body": "hello",
            "headers": {},
        }
        result = run(match_reply(parsed))
        self.assertEqual(result["method"], "unmatched")
        self.assertIsNone(result["lead"])
        processed = run(process_inbound(dict(parsed)))
        self.assertEqual(processed["match_method"], "unmatched")
        self.assertIsNone(processed["lead_id"])
        # Unmatched must NOT open a handoff.
        self.assertEqual(len(FAKE.handoffs), 0)

    def test_unmatched_reply_does_not_stop_followups(self):
        from inbound import process_inbound
        lead_id = FAKE.add_lead("ada@example.com")
        run(process_inbound({
            "external_id": "sg-noise",
            "from_address": "stranger@nowhere.example",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "wrong person",
            "body": "you have the wrong address",
            "headers": {},
        }))
        leads = run(fake_get_inbound_leads())
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["id"], lead_id)
        # And the noise must not mark the real lead replied.
        self.assertEqual(FAKE.replied_calls, [])


# ---------------------------------------------------------------------------
# 5. Classification
# ---------------------------------------------------------------------------

class ClassificationTests(unittest.TestCase):
    def test_all_required_classes(self):
        from inbound import classify_rules
        cases = [
            ("Please remove me from your list", "", "UNSUBSCRIBE"),
            ("unsubscribe", "", "UNSUBSCRIBE"),
            ("Stop contacting me", "", "UNSUBSCRIBE"),
            ("Do not contact us again", "", "UNSUBSCRIBE"),
            ("no more emails", "", "UNSUBSCRIBE"),
            ("Mail Delivery Subsystem", "Delivery has failed", "BOUNCE"),
            ("Out of office", "I am on vacation until Monday", "OUT_OF_OFFICE"),
            ("Re: report", "Not interested, thanks", "NOT_INTERESTED"),
            ("Re: report", "Yes we are interested - send pricing", "INTERESTED"),
            ("Re: report", "Can you explain how the TLS drift check works?", "QUESTION"),
            ("Random", "ok", "OTHER"),
        ]
        for subject, body, expected in cases:
            classification, confidence, evidence = classify_rules(subject, body)
            self.assertEqual(classification, expected,
                             msg=f"{subject!r}/{body!r} -> {classification} "
                                 f"(expected {expected}, evidence={evidence})")
            self.assertGreater(confidence, 0.0)

    def test_unsubscribe_beats_quoted_interest(self):
        from inbound import classify_rules
        classification, _, _ = classify_rules(
            "Re: assessment",
            "Not interested - please remove me from your list.\n"
            "Quoting: Yes we are interested")
        self.assertEqual(classification, "UNSUBSCRIBE")

    def test_llm_is_off_by_default(self):
        from inbound import _llm_enabled
        os.environ.pop("REPLY_LLM_CLASSIFY", None)
        self.assertFalse(_llm_enabled())
        os.environ["REPLY_LLM_CLASSIFY"] = "1"
        # Still requires GROQ key - we set a mock one in this file.
        self.assertTrue(_llm_enabled())
        os.environ.pop("REPLY_LLM_CLASSIFY", None)

    def test_decide_actions(self):
        from inbound import decide_actions
        self.assertTrue(decide_actions("UNSUBSCRIBE", True)["suppress"])
        self.assertTrue(decide_actions("BOUNCE", True)["suppress"])
        self.assertTrue(decide_actions("INTERESTED", True)["needs_human"])
        self.assertTrue(decide_actions("QUESTION", True)["needs_human"])
        self.assertFalse(decide_actions("NOT_INTERESTED", True)["needs_human"])
        self.assertTrue(decide_actions("NOT_INTERESTED", True)["stopped"])


# ---------------------------------------------------------------------------
# 6-9. Suppression, follow-up stop, handoffs
# ---------------------------------------------------------------------------

class SuppressionAndHandoffTests(InboundTestCase):
    def test_unsubscribe_suppresses_mailbox_wide(self):
        from inbound import process_inbound
        # Two sibling rows, same address (discovery re-open).
        FAKE.add_lead("ada@example.com", domain="a.example")
        FAKE.add_lead("ada@example.com", domain="b.example")
        FAKE.add_lead("other@corp.example", domain="c.example")

        run(process_inbound({
            "external_id": "sg-unsub",
            "from_address": "ada@example.com",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "unsubscribe",
            "body": "Please remove me from your list",
            "headers": {},
        }))

        self.assertTrue(FAKE.suppressed_calls)
        self.assertEqual(FAKE.suppressed_calls[0][0], "ada@example.com")
        for lead in FAKE.leads.values():
            if lead["email"] == "ada@example.com":
                self.assertEqual(lead["status"], "suppressed")
            else:
                self.assertNotEqual(lead["status"], "suppressed")
        # Follow-up selection must exclude the suppressed mailbox entirely.
        leads = run(fake_get_inbound_leads())
        emails = {l["email"] for l in leads}
        self.assertNotIn("ada@example.com", emails)

    def test_reply_stops_followups(self):
        from inbound import process_inbound
        lead_id = FAKE.add_lead("ada@example.com")
        # Before the reply the lead is eligible.
        self.assertEqual(len(run(fake_get_inbound_leads())), 1)

        run(process_inbound({
            "external_id": "sg-interested",
            "from_address": "ada@example.com",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "Re: assessment",
            "body": "Interested - let's talk",
            "headers": {},
        }))

        self.assertTrue(FAKE.replied_calls)
        self.assertEqual(FAKE.replied_calls[0][0], "ada@example.com")
        leads = run(fake_get_inbound_leads())
        self.assertEqual(leads, [])
        # And process_batch sends nothing.
        import outbound_engine
        engine = outbound_engine.OutboundEngine()
        engine._seeded_daily = True
        self.assertEqual(run(engine.process_batch()), 0)

    def test_interested_creates_handoff(self):
        from inbound import process_inbound
        lead_id = FAKE.add_lead("ada@example.com", domain="example.com")
        result = run(process_inbound({
            "external_id": "sg-int",
            "from_address": "ada@example.com",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "Re: assessment",
            "body": "Interested - can we schedule a call?",
            "headers": {},
        }))
        self.assertEqual(result["classification"], "INTERESTED")
        self.assertTrue(result["needs_human"])
        self.assertIsNotNone(result["handoff_id"])
        self.assertEqual(len(FAKE.handoffs), 1)
        handoff = FAKE.handoffs[0]
        self.assertEqual(handoff["classification"], "INTERESTED")
        self.assertIn("ada@example.com", handoff["title"])
        self.assertIn("example.com", handoff["detail"])
        self.assertEqual(handoff["status"], "open")
        self.assertEqual(handoff["lead_id"], lead_id)

    def test_question_creates_handoff(self):
        from inbound import process_inbound
        FAKE.add_lead("bob@corp.example", domain="corp.example")
        result = run(process_inbound({
            "external_id": "sg-q",
            "from_address": "bob@corp.example",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "Re: assessment",
            "body": "How does the continuous monitoring feed work?",
            "headers": {},
        }))
        self.assertEqual(result["classification"], "QUESTION")
        self.assertTrue(result["needs_human"])
        self.assertEqual(len(FAKE.handoffs), 1)

    def test_not_interested_stops_but_no_handoff(self):
        from inbound import process_inbound
        FAKE.add_lead("ada@example.com")
        result = run(process_inbound({
            "external_id": "sg-ni",
            "from_address": "ada@example.com",
            "recipient": "replies@zerodaysentinel.xo.je",
            "subject": "Re: assessment",
            "body": "Not interested, thanks",
            "headers": {},
        }))
        self.assertEqual(result["classification"], "NOT_INTERESTED")
        self.assertTrue(result["stopped_followups"])
        self.assertFalse(result["needs_human"])
        self.assertEqual(len(FAKE.handoffs), 0)

    def test_bounce_suppresses(self):
        from inbound import process_inbound
        FAKE.add_lead("dead@example.com")
        result = run(process_inbound({
            "external_id": "sg-bounce",
            "from_address": "mailer-daemon@zerodaysentinel.xo.je",
            "recipient": "updates@zerodaysentinel.xo.je",
            "subject": "Mail delivery failed",
            "body": "Final-Recipient: rfc822; dead@example.com\nAction: failed",
            "headers": {},
        }))
        self.assertEqual(result["classification"], "BOUNCE")
        self.assertTrue(result["suppressed"])
        self.assertTrue(any(addr == "dead@example.com"
                            for addr, _ in FAKE.suppressed_calls))

    def test_event_webhook_bounce_suppresses(self):
        from inbound import process_sendgrid_events
        FAKE.add_lead("gone@example.com")
        result = run(process_sendgrid_events([
            {"event": "delivered", "email": "ok@example.com"},
            {"event": "bounce", "email": "gone@example.com", "reason": "550"},
            {"event": "open", "email": "ok@example.com"},
        ]))
        self.assertEqual(result["processed"], 3)
        self.assertEqual(result["suppressed"], 1)
        self.assertTrue(any(a == "gone@example.com" for a, _ in FAKE.suppressed_calls))


# ---------------------------------------------------------------------------
# Webhook secret + API wiring smoke (no TestClient dependency)
# ---------------------------------------------------------------------------

class WebhookAuthTests(unittest.TestCase):
    def test_secret_unset_allows(self):
        from inbound import webhook_secret_ok
        os.environ.pop("INBOUND_WEBHOOK_SECRET", None)
        self.assertTrue(webhook_secret_ok(""))

    def test_secret_set_requires_match(self):
        from inbound import webhook_secret_ok
        os.environ["INBOUND_WEBHOOK_SECRET"] = "s3cret-value"
        try:
            self.assertFalse(webhook_secret_ok(""))
            self.assertFalse(webhook_secret_ok("wrong"))
            self.assertTrue(webhook_secret_ok("s3cret-value"))
        finally:
            os.environ.pop("INBOUND_WEBHOOK_SECRET", None)

    def test_api_exposes_expected_routes(self):
        import api
        paths = {getattr(r, "path", None) for r in api.app.routes}
        self.assertIn("/webhook/sendgrid/inbound", paths)
        self.assertIn("/webhook/sendgrid/events", paths)
        self.assertIn("/internal/inbound", paths)
        self.assertIn("/internal/handoffs", paths)
        # Existing production routes must still exist.
        self.assertIn("/health", paths)
        self.assertIn("/internal/run-batch", paths)
        self.assertIn("/unsubscribe", paths)
        self.assertIn("/webhook/paypal", paths)


class OutboundStageProtectionTests(InboundTestCase):
    def test_stage_already_sent_is_skipped(self):
        import outbound_engine
        from datetime import datetime
        lead_id = FAKE.add_lead("ada@example.com")
        # Mark whichever stage the day-gate will compute for a just-updated lead.
        engine_probe = outbound_engine.OutboundEngine()
        stage = engine_probe._get_follow_up_stage(FAKE.leads[lead_id])
        FAKE.stages[(lead_id, stage)] = "sent"
        engine = outbound_engine.OutboundEngine()
        engine._seeded_daily = True
        engine.emails_sent_today = 0
        self.assertEqual(run(engine.process_batch()), 0)

    def test_get_inbound_leads_excludes_replied_mailbox(self):
        lead_id = FAKE.add_lead("ada@example.com")
        FAKE.add_lead("ada@example.com", domain="other.example")
        run(fake_mark_mailbox_replied("ada@example.com", "INTERESTED"))
        leads = run(fake_get_inbound_leads())
        self.assertEqual(leads, [])
        # Sibling row also gone.
        self.assertEqual(FAKE.leads[lead_id]["status"], "replied")


if __name__ == "__main__":
    unittest.main(verbosity=2)
