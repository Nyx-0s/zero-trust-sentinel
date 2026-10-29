"""Focused regression tests for the Resilient Brain patch (commit 96c9b9d).

Covers, without any network or database:
  * the token bucket throttling a burst and settling back up,
  * the disabled limiter (GROQ_TPM_LIMIT=0),
  * run_scan retrying Groq 429 with the server-stated delay, bounded,
  * non-429 errors raising immediately (no inappropriate retry),
  * the signals argument surviving into the graph state,
  * failed lead tasks persisting a real error + timestamp on BOTH failure
    branches (exception path and the DNS/scanner fast-fail path),
  * business_intel sharing the same limiter and retry helpers.

Run:  python test_resilient_brain.py
"""

import asyncio
import os
import time
import unittest
from typing import Any, Dict, List, Optional

import api
import business_intel as bi
import main
from main import GroqRateLimiter


class FakeResponse:
    def __init__(self, content: str, total_tokens: int = 100) -> None:
        self.content = content
        self.usage_metadata = {"total_tokens": total_tokens}


class FakeGraph:
    """Stand-in for the compiled LangGraph app (records the state it got)."""

    def __init__(self, plan: List[BaseException]) -> None:
        self.plan = plan
        self.calls: List[Dict[str, Any]] = []

    async def ainvoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(dict(state))
        action = self.plan.pop(0) if self.plan else None
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(dict(state))
        return dict(state, executive_summary="ok", risk_score=95)


class RateLimiterTests(unittest.TestCase):
    def test_burst_is_throttled_and_settles_back_up(self):
        async def scenario():
            bucket = GroqRateLimiter(max_tokens_per_minute=6000, call_cost=1000)
            bucket.tokens = 0.0  # simulate an empty minute
            started = time.monotonic()
            hold = await bucket.acquire(20)          # 20 tokens at 100/s
            elapsed = time.monotonic() - started
            self.assertAlmostEqual(hold, 20.0)
            self.assertGreaterEqual(elapsed, 0.15)   # it had to wait
            self.assertLess(elapsed, 2.0)

            # settle() refunds the unused part of a spent hold
            before = bucket.tokens
            await bucket.settle(1000, FakeResponse("x", total_tokens=100))
            self.assertGreater(bucket.tokens, before)
            self.assertLessEqual(bucket.tokens, bucket.max_tokens)

        asyncio.run(scenario())

    def test_overspend_is_debited_not_ignored(self):
        """A call that cost MORE than its hold must drain the bucket.

        Refunding only was the 18:19 burst bug: three concurrent scans each
        held 1,500, each actually spent ~4k+, and the bucket never noticed -
        so we kept launching calls Groq had already counted against its
        8,000 TPM and everything 429'd.
        """
        async def scenario():
            bucket = GroqRateLimiter(max_tokens_per_minute=7500, call_cost=1500)
            hold = await bucket.acquire(1500)
            before = bucket.tokens
            await bucket.settle(hold, FakeResponse("x", total_tokens=5200))
            # (a sliver of refill accrues while the call is in flight)
            self.assertAlmostEqual(bucket.tokens, before - 3700, delta=0.5)

        asyncio.run(scenario())

    def test_estimate_covers_prompt_plus_reasoning_allowance(self):
        async def scenario():
            bucket = GroqRateLimiter(max_tokens_per_minute=7500, call_cost=1500)
            messages = [type("M", (), {"content": "x" * 4000})()]
            estimate = bucket.estimate_call(messages)
            # 4,000 chars ~= 1,000 prompt tokens + the reasoning allowance
            self.assertGreaterEqual(estimate, 1000 + main.GROQ_COMPLETION_ALLOWANCE)
            self.assertLessEqual(estimate, bucket.max_tokens)
            self.assertGreater(bucket.estimate_call([]), 0)

        asyncio.run(scenario())

    def test_disabled_limiter_never_waits(self):
        async def scenario():
            bucket = GroqRateLimiter(max_tokens_per_minute=0, call_cost=999999)
            started = time.monotonic()
            hold = await bucket.acquire()
            self.assertEqual(hold, 0.0)
            self.assertLess(time.monotonic() - started, 0.2)

        asyncio.run(scenario())

    def test_default_configuration_is_the_documented_budget(self):
        self.assertEqual(main.GROQ_TPM_LIMIT, 7500)
        self.assertEqual(main.GROQ_CALL_TOKENS, 1500)
        self.assertIsNotNone(main.groq_limiter)


class RetryPolicyTests(unittest.TestCase):
    def setUp(self):
        self._app = main.app

    def tearDown(self):
        main.app = self._app

    def test_delay_parses_groq_stated_wait_and_falls_back(self):
        delay = main._rate_limit_delay(
            Exception("Error code: 429 - Please try again in 24.615s"), 1)
        self.assertAlmostEqual(delay, 24.615, places=3)
        self.assertEqual(main._rate_limit_delay(Exception("429"), 1), 30.0)
        self.assertEqual(main._rate_limit_delay(Exception("429"), 5), 120.0)  # capped

    def test_rate_limit_wait_is_bounded_by_the_invocation_budget(self):
        """A cap that never lifts must YIELD, not sleep past the platform's
        execution deadline (Vercel kills the function at 300s, which would
        turn a rate-limited lead into a dead one)."""
        main.app = FakeGraph([Exception("429 - Please try again in 120s"),
                              Exception("429 - Please try again in 120s")])
        saved = os.environ.get("RATE_LIMIT_MAX_WAIT")
        # run_scan flips the shared client to the fallback model on the way to
        # giving up; put it back so later tests see the primary.
        model_state = (main._current_model, main.llm.model_name)
        os.environ["RATE_LIMIT_MAX_WAIT"] = "10"
        try:
            with self.assertRaises(RuntimeError):
                asyncio.run(main.run_scan("example.com"))
        finally:
            if saved is None:
                os.environ.pop("RATE_LIMIT_MAX_WAIT", None)
            else:
                os.environ["RATE_LIMIT_MAX_WAIT"] = saved
            main._current_model, main.llm.model_name = model_state

    def test_429_is_detected_and_other_errors_are_not(self):
        self.assertTrue(main._is_rate_limit_error(Exception("429 Many Requests")))
        self.assertTrue(main._is_rate_limit_error(Exception("Rate limit reached")))
        self.assertFalse(main._is_rate_limit_error(ValueError("bad payload")))

    def test_rate_limit_switches_the_shared_client_to_the_other_model(self):
        """Groq caps tokens per model per day, so a capped primary must hand
        the scan to the sibling model instead of burning every retry."""
        saved = (main._current_model, main.llm.model_name)
        try:
            main._current_model = main.GROQ_MODEL_PRIMARY
            main.llm.model_name = main.GROQ_MODEL_PRIMARY
            first = main.switch_model()
            self.assertEqual(first, main.GROQ_MODEL_FALLBACK)
            self.assertEqual(main.llm.model_name, main.GROQ_MODEL_FALLBACK)
            # it toggles, so the primary is retried once it has budget again
            self.assertEqual(main.switch_model(), main.GROQ_MODEL_PRIMARY)
        finally:
            main._current_model, main.llm.model_name = saved

    def test_switch_is_a_no_op_when_only_one_model_is_configured(self):
        saved = (main.GROQ_MODEL_FALLBACK, main._current_model, main.llm.model_name)
        try:
            main.GROQ_MODEL_FALLBACK = main.GROQ_MODEL_PRIMARY
            self.assertIsNone(main.switch_model())
        finally:
            main.GROQ_MODEL_FALLBACK, main._current_model, main.llm.model_name = saved

    def test_run_scan_retries_429_then_succeeds(self):
        main.app = FakeGraph([
            Exception("429 - Please try again in 1s"),
            Exception("429 - Please try again in 1s"),
        ])
        result = asyncio.run(main.run_scan("example.com", signals=["exposed_api"]))
        self.assertEqual(len(main.app.calls), 3)          # 2 failures + success
        self.assertEqual(result["executive_summary"], "ok")
        self.assertEqual(main.app.calls[0]["signals"], ["exposed_api"])

    def test_run_scan_gives_up_after_max_retries(self):
        main.app = FakeGraph(
            [Exception("429 - Please try again in 1s")] * 10)
        with self.assertRaises(Exception):
            asyncio.run(main.run_scan("example.com", max_retries=3))
        self.assertEqual(len(main.app.calls), 3)          # bounded, not endless

    def test_non_429_raises_immediately(self):
        main.app = FakeGraph([RuntimeError("DNS resolution failed")])
        with self.assertRaises(RuntimeError):
            asyncio.run(main.run_scan("example.com"))
        self.assertEqual(len(main.app.calls), 1)          # no retry storm

    def test_signals_and_max_retries_share_the_signature(self):
        import inspect
        sig = inspect.signature(main.run_scan)
        self.assertIn("signals", sig.parameters)
        self.assertIn("max_retries", sig.parameters)


class FailurePersistenceTests(unittest.TestCase):
    """metadata.error must carry the real message on every failure branch."""

    def setUp(self):
        self.meta: Dict[int, Dict[str, Any]] = {}
        self.statuses: Dict[int, str] = {}

        async def fake_meta(task_id: int, payload: Dict[str, Any]) -> None:
            self.meta[task_id] = payload

        async def fake_status(task_id: int, status: str) -> None:
            self.statuses[task_id] = status

        self._patchers = [
            ("update_lead_task_metadata", fake_meta),
            ("update_lead_task_status", fake_status),
        ]
        self._originals = {}
        for name, fn in self._patchers:
            self._originals[name] = getattr(api, name)
            setattr(api, name, fn)

    def tearDown(self):
        for name, _ in self._patchers:
            setattr(api, name, self._originals[name])

    def test_fail_lead_task_records_error_and_timestamp(self):
        asyncio.run(api._fail_lead_task(7, "Groq 429 quota exhausted"))
        self.assertEqual(self.meta[7]["error"], "Groq 429 quota exhausted")
        self.assertIn("failed_at", self.meta[7])
        self.assertTrue(self.meta[7]["failed_at"].endswith("Z"))
        self.assertEqual(self.statuses[7], "failed")

    def test_fast_fail_branch_persists_too(self):
        """A scanner error (DNS fast-fail) is persisted, not just raised."""
        import scanners

        async def fake_get(task_id: int):
            return {"id": task_id, "updated_at": None, "status": "pending"}

        async def fake_claim(task_id: int, observed):
            return True

        async def fake_signals(domain: str):
            return []

        async def fake_scan(domain: str):
            return {"domain": domain, "error": "DNS resolution failed"}

        originals = {
            "get_lead_task": api.get_lead_task,
            "claim_lead_task": api.claim_lead_task,
            "get_lead_signals": api.get_lead_signals,
            "run_full_scan": scanners.run_full_scan,
        }
        api.get_lead_task = fake_get
        api.claim_lead_task = fake_claim
        api.get_lead_signals = fake_signals
        scanners.run_full_scan = fake_scan
        try:
            asyncio.run(api.process_lead_scan(
                11, "does-not-exist-xyz.invalid", "a@b.c", "Ada"))
        finally:
            for name, fn in originals.items():
                if name == "run_full_scan":
                    scanners.run_full_scan = fn
                else:
                    setattr(api, name, fn)

        self.assertEqual(self.meta[11]["error"], "DNS resolution failed")
        self.assertIn("failed_at", self.meta[11])
        self.assertEqual(self.statuses[11], "failed")


class SharedInfrastructureTests(unittest.TestCase):
    def test_business_module_reuses_the_scan_limiter_and_helpers(self):
        self.assertIs(bi.groq_limiter, main.groq_limiter)
        self.assertIs(bi._is_rate_limit_error, main._is_rate_limit_error)
        self.assertIs(bi._rate_limit_delay, main._rate_limit_delay)


if __name__ == "__main__":
    unittest.main(verbosity=2)
