"""Tests for Sentinel's business-intelligence module (business_intel.py).

What this suite guards:

  * the skill registry: ids, order, capability classes, input validation
  * the project constraint that founder-skill is an ANALYSIS framework only -
    no vendored copy, no runtime path into that repository anywhere in this
    product's source
  * honest failure: research skills refuse without supplied evidence, an
    unconfigured model is reported as unavailable and never replaced by
    generated content
  * the workflow runs every registered skill in order and records each outcome
  * the /business routes: validation, persistence seams, honest status codes

Run:  python test_business_intel.py
"""

import asyncio
import json
import subprocess  # noqa: F401  (kept: the suite shells out for repo checks)
import sys
import unittest
from pathlib import Path

import business_intel as bi

REPO = Path(__file__).resolve().parent
WORKFLOW_PID = 910003


def run(coro):
    return asyncio.run(coro)


class NoVendoredFrameworkTests(unittest.TestCase):
    """founder-skill may inform the analysis; it must never ship or run."""

    def test_registry_is_self_contained(self):
        self.assertEqual(set(bi.WORKFLOW_ORDER), set(bi.SKILLS))
        self.assertTrue((REPO / "business_intel.py").is_file())
        # Instructions live in this module, not in files from another repo.
        for skill_id in bi.WORKFLOW_ORDER:
            self.assertIn(skill_id, bi.SKILL_INSTRUCTIONS)
            self.assertTrue(bi.SKILL_INSTRUCTIONS[skill_id].strip(),
                            f"empty instructions for {skill_id}")

    def test_module_never_reads_an_external_skill_tree(self):
        src = (REPO / "business_intel.py").read_text(encoding="utf-8")
        for marker in ("vendor/founder-skill", "VENDOR_SKILLS", "_skill_md",
                       "_run_tool", "_script_path"):
            self.assertNotIn(marker, src,
                             f"{marker} reintroduces the dependency")

    def test_no_product_source_references_the_external_repo(self):
        """Python, JS, HTML, Dockerfile: nothing may point at that tree."""
        patterns = ("vendor/founder-skill", "founder-skill.git")
        checked = 0
        skip = {".git", ".venv", "node_modules", "business_work", "__pycache__"}
        for path in REPO.rglob("*"):
            if not path.is_file() or path.name.startswith("."):
                continue
            if any(part in skip for part in path.parts):
                continue
            if path.suffix not in (".py", ".js", ".html", ".css", ".md",
                                   ".yml", ".yaml", ".json", "") and \
                    path.name != "Dockerfile":
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            checked += 1
            for marker in patterns:
                if marker in text and path.name != "test_business_intel.py":
                    self.fail(f"{path.relative_to(REPO)} references {marker}")
        self.assertGreater(checked, 10, "the source sweep found nothing to read")

    def test_vendored_tree_is_not_shipped(self):
        self.assertFalse((REPO / "vendor" / "founder-skill").exists(),
                         "the external framework must not be vendored")


class RegistryTests(unittest.TestCase):
    def test_registry_kinds_and_order(self):
        reg = bi.get_registry()
        self.assertEqual(len(reg), len(bi.WORKFLOW_ORDER))
        self.assertEqual([s["id"] for s in reg], bi.WORKFLOW_ORDER)
        kinds = {s["id"]: s["kind"] for s in reg}
        self.assertEqual(kinds["founder-competitors"], "research")
        for skill_id, kind in kinds.items():
            self.assertIn(kind, ("llm", "research"),
                          f"{skill_id} must not require an external tool")
        # The first analysis step is the board; launch closes the sequence.
        self.assertEqual(bi.WORKFLOW_ORDER[0], "founder-board")
        self.assertEqual(bi.WORKFLOW_ORDER[-1], "founder-launch")

    def test_unknown_skill_is_rejected(self):
        with self.assertRaises(bi.SkillInputError):
            bi.validate_skill_id("founder-definitely-not")

    def test_oversized_inputs_are_rejected(self):
        with self.assertRaises(bi.SkillInputError):
            run(bi.run_skill(910003, "founder-board", {},
                             {"pad": "x" * (bi.MAX_INPUT_BYTES + 100)}))

    def test_every_skill_has_a_summary_for_the_cockpit(self):
        for skill_id, spec in bi.SKILLS.items():
            self.assertTrue(spec.get("summary"), skill_id)
            self.assertTrue(spec.get("title"), skill_id)


class PromptTests(unittest.TestCase):
    def test_prompt_carries_instructions_context_and_hard_rules(self):
        prompt = bi.build_prompt(
            "founder-offer", bi.SENTINEL_CONTEXT_TEMPLATE,
            {"note": "x"}, [], [{"url": "https://example.com", "note": "price"}])
        self.assertIn(bi.SKILL_INSTRUCTIONS["founder-offer"], prompt)
        self.assertIn("Zero-Trust Sentinel", prompt)
        self.assertIn("Never invent customers", prompt)
        self.assertIn("https://example.com", prompt)

    def test_missing_instructions_fail_honestly(self):
        with self.assertRaises(bi.SkillUnavailable):
            bi.build_prompt("not-a-real-skill", {}, {}, [], [])


class HonestyTests(unittest.TestCase):
    def test_research_skill_refuses_without_evidence_and_never_calls_model(self):
        async def exploding(*a, **k):
            raise AssertionError("model must not be called without evidence")

        original = bi._run_llm
        bi._run_llm = exploding
        try:
            result = run(bi.run_skill(910020, "founder-competitors",
                                      bi.SENTINEL_CONTEXT_TEMPLATE, {}))
        finally:
            bi._run_llm = original
        self.assertEqual(result["status"], "needs_research")
        self.assertIn("evidence", result["error"])
        self.assertEqual(result["content"], "")

    def test_research_skill_runs_once_evidence_is_supplied(self):
        seen = {}

        async def fake_llm(skill_id, context, inputs, prior, evidence):
            seen["evidence"] = evidence
            return {"kind": "llm", "status": "complete",
                    "content": "# Competition\nsource: https://example.com",
                    "output": {}, "error": None, "meta": {}}

        original = bi._run_llm
        bi._run_llm = fake_llm
        try:
            result = run(bi.run_skill(
                910021, "founder-competitors", bi.SENTINEL_CONTEXT_TEMPLATE,
                {"evidence": [{"url": "https://example.com/pricing",
                               "note": "published price list"}]}))
        finally:
            bi._run_llm = original
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(seen["evidence"]), 1)
        self.assertEqual(result["meta"]["evidence_status"], "supplied_by_user")

    def test_model_unavailable_is_an_honest_error(self):
        original_configured = bi.LLM_CONFIGURED
        bi.LLM_CONFIGURED = False
        try:
            result = run(bi.run_skill(910022, "founder-board",
                                      bi.SENTINEL_CONTEXT_TEMPLATE, {}))
        finally:
            bi.LLM_CONFIGURED = original_configured
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["error"].startswith("model_unavailable"))
        self.assertEqual(result["content"], "")

    def test_context_fingerprint_is_stable(self):
        first = bi.context_fingerprint(bi.SENTINEL_CONTEXT_TEMPLATE)
        second = bi.context_fingerprint(bi.SENTINEL_CONTEXT_TEMPLATE)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 16)


class WorkflowTests(unittest.TestCase):
    def test_workflow_runs_every_skill_in_order_and_records_each(self):
        stored = {}

        async def fake_llm(skill_id, context, inputs, prior, evidence):
            return {"kind": "llm", "status": "complete",
                    "content": f"# {skill_id}\n\nFixture document.",
                    "output": {}, "error": None, "meta": {"generated_by": "llm"}}

        async def fetch_prior(pid):
            return [dict(v, skill_id=k) for k, v in stored.items()]

        async def recorder(skill_id, result):
            stored[skill_id] = result

        original_llm = bi._run_llm
        bi._run_llm = fake_llm
        bi.set_recorder(recorder)
        try:
            results = run(bi.run_workflow(WORKFLOW_PID,
                                          bi.SENTINEL_CONTEXT_TEMPLATE,
                                          {}, fetch_prior=fetch_prior))
        finally:
            bi._run_llm = original_llm
            bi.set_recorder(None)

        self.assertEqual(len(results), len(bi.WORKFLOW_ORDER))
        self.assertEqual([r["skill_id"] for r in results], bi.WORKFLOW_ORDER)
        by_id = {r["skill_id"]: r for r in results}
        for skill_id in bi.WORKFLOW_ORDER:
            if skill_id == "founder-competitors":
                # no evidence supplied: honestly gated, never invented
                self.assertEqual(by_id[skill_id]["status"], "needs_research")
            else:
                self.assertEqual(by_id[skill_id]["status"], "complete",
                                 f"{skill_id}: {by_id[skill_id].get('error')}")
                self.assertIn("Fixture document.", by_id[skill_id]["content"])
        # every outcome was persisted through the recorder seam
        self.assertEqual(set(stored), set(bi.WORKFLOW_ORDER))


class ApiRouteTests(unittest.TestCase):
    """The /business routes: validation, persistence seams, honest status codes."""

    @classmethod
    def setUpClass(cls):
        import api
        cls.api = api
        cls._originals = {}

        cls.projects = {}
        cls.outputs = {}
        cls.next_id = [1]

        async def create(name, context=None):
            pid = cls.next_id[0]
            cls.next_id[0] += 1
            cls.projects[pid] = {"id": pid, "name": name,
                                 "context": context or {}, "status": "active"}
            return pid

        async def get(pid):
            return cls.projects.get(pid)

        async def listing():
            return [dict(p, complete=0, failed=0, outputs=0)
                    for p in cls.projects.values()]

        async def save(pid, skill_id, status, kind="", content="", output=None,
                       error=None, meta=None):
            cls.outputs[(pid, skill_id)] = {
                "project_id": pid, "skill_id": skill_id, "status": status,
                "kind": kind, "content": content, "output": output or {},
                "error": error, "meta": meta or {}}

        async def outputs_for(pid):
            return [dict(v, content_length=len(v["content"] or ""))
                    for (p, _), v in cls.outputs.items() if p == pid]

        async def output_for(pid, skill_id):
            return cls.outputs.get((pid, skill_id))

        async def update_context(pid, context):
            cls.projects[pid]["context"] = context

        cls.fakes = {
            "create_business_project": create,
            "get_business_project": get,
            "list_business_projects": listing,
            "save_business_output": save,
            "get_business_outputs": outputs_for,
            "get_business_output": output_for,
            "update_business_project_context": update_context,
        }
        for name, fn in cls.fakes.items():
            cls._originals[name] = getattr(api, name)
            setattr(api, name, fn)

        from fastapi.testclient import TestClient
        cls.client = TestClient(api.app)   # no context manager: no startup,
                                           # so no database connection happens

    @classmethod
    def tearDownClass(cls):
        for name, fn in cls._originals.items():
            setattr(cls.api, name, fn)

    def test_01_skills_endpoint(self):
        res = self.client.get("/business/skills")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["skills"]), len(bi.WORKFLOW_ORDER))
        self.assertNotIn("/Users/", res.text)      # no host file-system paths
        self.assertNotIn("vendor/founder-skill", res.text)

    def test_02_context_template(self):
        res = self.client.get("/business/context-template")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("product", body)
        self.assertIsNone(body["metrics"]["mrr"])  # no invented revenue

    def test_03_create_validates_name(self):
        self.assertEqual(
            self.client.post("/business/projects",
                             json={"name": ""}).status_code, 400)
        ok = self.client.post("/business/projects",
                              json={"name": "Test plan", "context": {}})
        self.assertEqual(ok.status_code, 200)
        self.assertGreaterEqual(ok.json()["id"], 1)

    def test_04_unknown_project_and_output_404(self):
        self.assertEqual(self.client.get("/business/projects/999999").status_code,
                         404)
        self.assertEqual(
            self.client.get(
                "/business/projects/1/outputs/founder-board").status_code, 404)
        self.assertEqual(
            self.client.post("/business/projects/1/run",
                             json={"skill_id": "not-a-skill"}).status_code, 400)

    def test_05_workflow_run_marks_every_skill_pending(self):
        pid = self.client.post("/business/projects",
                               json={"name": "Workflow run"}).json()["id"]
        res = self.client.post(f"/business/projects/{pid}/run",
                               json={"skill_id": "workflow"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()["skills"]), len(bi.WORKFLOW_ORDER))
        state = self.client.get(f"/business/projects/{pid}").json()
        statuses = {o["skill_id"]: o["status"] for o in state["outputs"]}
        self.assertEqual(len(statuses), len(bi.WORKFLOW_ORDER))
        self.assertTrue(all(s in ("pending", "running", "complete",
                                  "failed", "needs_research")
                            for s in statuses.values()))

    def test_06_context_replacement_roundtrip(self):
        pid = self.client.post("/business/projects",
                               json={"name": "Context"}).json()["id"]
        res = self.client.post(f"/business/projects/{pid}/context",
                               json={"context": {"product": {"name": "X"}}})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["context"]["product"]["name"], "X")


class ErrorHandlingTests(unittest.TestCase):
    def test_500_handler_does_not_leak_internals(self):
        import api
        from starlette.requests import Request

        request = Request({"type": "http", "method": "GET", "path": "/boom",
                           "headers": [], "query_string": b"",
                           "server": ("127.0.0.1", 8080),
                           "client": ("127.0.0.1", 1)})
        exc = RuntimeError("postgresql://user:hunter2@db:5432/secret "
                           "GROQ_API_KEY=gsk_secret")
        response = asyncio.run(
            api.generic_exception_handler(request, exc))
        body = response.body.decode("utf-8")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("hunter2", body)
        self.assertNotIn("gsk_secret", body)
        self.assertIn("RuntimeError", body)   # type only, useful but safe


if __name__ == "__main__":
    unittest.main(verbosity=2)
