"""Integration tests for the Sentinel business-intelligence module.

Covers (Section 7B of the integration spec):
  * the vendored founder-skill tree: 11 skills, MIT licence, upstream tests,
  * deterministic tools on valid and invalid fixtures,
  * the research gate refusing to run without sources (and never calling the
    model to paper over it),
  * honest model-unavailable errors (no fabricated output),
  * the full eleven-skill workflow producing a compiled plan,
  * the /business API routes: validation, persistence hooks, 400/404 handling,
  * the 500 handler not echoing internals.

Run:  python test_business_intel.py
"""

import asyncio
import json
import subprocess
import sys
import unittest
from pathlib import Path

import business_intel as bi

REPO = Path(__file__).resolve().parent
VENDOR = REPO / "vendor" / "founder-skill"
SKILLS = VENDOR / "skills"
EXAMPLE_NUMBERS = SKILLS / "founder-cfo" / "example.json"
EXAMPLE_CUSTOMER = SKILLS / "founder-consumer" / "customer.example.json"
EXAMPLE_PITCH = SKILLS / "founder-consumer" / "pitch.example.md"

# Unique workdir project ids so tests never touch real project data.
PANEL_PID = 910001
PRICING_PID = 910002
WORKFLOW_PID = 910003


def run(coro):
    return asyncio.run(coro)


class VendorTreeTests(unittest.TestCase):
    def test_all_eleven_skills_and_instructions_exist(self):
        for skill_id in bi.WORKFLOW_ORDER:
            self.assertTrue((SKILLS / skill_id / "SKILL.md").is_file(),
                            f"missing SKILL.md for {skill_id}")
        self.assertEqual(len(bi.WORKFLOW_ORDER), 11)
        self.assertEqual(set(bi.WORKFLOW_ORDER), set(bi.SKILLS))

    def test_mit_licence_retained_with_upstream_copyright(self):
        licence = (VENDOR / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", licence)
        self.assertIn("Jake Schincariol", licence)
        vendor_md = (VENDOR / "VENDOR.md").read_text(encoding="utf-8")
        self.assertIn("Jakeschincariol/founder-skill", vendor_md)
        self.assertIn("fd9385b0", vendor_md)

    def test_upstream_test_suite_passes_unmodified(self):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=str(VENDOR), capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("OK", proc.stderr + proc.stdout)

    def test_tools_are_python38_compatible_standard_library_scripts(self):
        for rel in ("founder-cfo/unit_economics.py",
                    "founder-consumer/panel.py",
                    "founder-pricing/van_westendorp.py",
                    "founder-plan/compile.py"):
            path = SKILLS / rel
            src = path.read_text(encoding="utf-8")
            self.assertNotIn("import requests", src)
            compile(src, str(path), "exec")   # syntax check on this interpreter


class RegistryTests(unittest.TestCase):
    def test_registry_kinds_and_order(self):
        reg = bi.get_registry()
        self.assertEqual(len(reg), 11)
        self.assertEqual([s["id"] for s in reg], bi.WORKFLOW_ORDER)
        kinds = {s["id"]: s["kind"] for s in reg}
        self.assertEqual(kinds["founder-competitors"], "research")
        for tool in ("founder-consumer", "founder-pricing",
                     "founder-cfo", "founder-plan"):
            self.assertEqual(kinds[tool], "tool")
        for llm_skill in ("founder-board", "founder-offer", "founder-marketing",
                          "founder-brand", "founder-ops", "founder-launch"):
            self.assertEqual(kinds[llm_skill], "llm")

    def test_unknown_skill_is_rejected(self):
        with self.assertRaises(bi.SkillInputError):
            bi.validate_skill_id("founder-definitely-not")

    def test_registry_scripts_cannot_escape_the_vendor_tree(self):
        for skill_id, spec in bi.SKILLS.items():
            if "tool" not in spec:
                continue
            path = bi._script_path(skill_id)
            self.assertTrue(str(path).startswith(str(SKILLS.resolve())))
        # A hostile registry entry is refused, not executed.
        original = dict(bi.SKILLS["founder-cfo"]["tool"])
        bi.SKILLS["founder-cfo"]["tool"]["script"] = "../../../etc/passwd"
        try:
            with self.assertRaises(bi.SkillUnavailable):
                bi._script_path("founder-cfo")
        finally:
            bi.SKILLS["founder-cfo"]["tool"] = original

    def test_oversized_inputs_are_rejected(self):
        with self.assertRaises(bi.SkillInputError):
            run(bi.run_skill(PANEL_PID, "founder-cfo", {},
                             {"numbers": {"pad": "x" * (bi.MAX_INPUT_BYTES + 100)}}))


class DeterministicToolTests(unittest.TestCase):
    def test_unit_economics_correct_on_known_inputs(self):
        numbers = json.loads(EXAMPLE_NUMBERS.read_text(encoding="utf-8"))
        # Independent arithmetic: 6.50 - (0.92 + 0.38 + 0.24 + 0.20) = 4.76
        price = numbers["price"]
        variable = sum(v["cost"] for v in numbers["variable"])
        self.assertAlmostEqual(price - variable, 4.76, places=2)

        result = run(bi.run_skill(910010, "founder-cfo", {},
                                  {"numbers": numbers}))
        self.assertEqual(result["status"], "complete", result.get("error"))
        self.assertIn("4.76", result["content"])
        self.assertIn("6.50", result["content"])
        self.assertEqual(result["kind"], "tool")

    def test_unit_economics_rejects_invalid_input_honestly(self):
        result = run(bi.run_skill(910011, "founder-cfo", {},
                                  {"numbers": {"business": "x"}}))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["content"], "")           # nothing fabricated
        self.assertIn("'price' is missing", result["error"])
        self.assertIn("rejected the inputs", result["error"])

    def test_panel_init_status_and_tally_without_answers(self):
        customer = json.loads(EXAMPLE_CUSTOMER.read_text(encoding="utf-8"))
        pitch = EXAMPLE_PITCH.read_text(encoding="utf-8")
        init = run(bi.run_skill(PANEL_PID, "founder-consumer", {},
                                {"op": "init", "customer": customer,
                                 "pitch": pitch, "n": 6}))
        self.assertEqual(init["status"], "complete", init.get("error"))
        self.assertIn("6 buyers", init["content"])

        status = run(bi.run_skill(PANEL_PID, "founder-consumer", {}, {}))
        self.assertEqual(status["status"], "complete", status.get("error"))
        self.assertIn("buyers dealt", status["content"])

        # No answers yet: an honest failure, not an invented tally.
        tally = run(bi.run_skill(PANEL_PID, "founder-consumer", {},
                                 {"op": "tally"}))
        self.assertEqual(tally["status"], "failed")
        self.assertEqual(tally["content"], "")

    def test_panel_saves_valid_answers_then_tallies(self):
        founder = bi.workdir_for(PANEL_PID)
        personas = json.loads((founder / "panel" / "personas.json")
                               .read_text(encoding="utf-8"))
        reason = sorted(_panel_reasons())[0]
        for persona in personas:
            answer = {
                "id": persona["id"],
                "buys": True,
                "purchases_first_month": 4,
                "reason_code": reason,
                "reason": "I buy coffee most days anyway.",
                "objection": "the queue at my usual place",
                "would_change_my_mind": "a loyalty card",
                "price_too_cheap": 3.0,
                "price_cheap": 5.5,
                "price_expensive": 7.5,
                "price_too_expensive": 9.0,
            }
            saved = run(bi.run_skill(PANEL_PID, "founder-consumer", {},
                                     {"op": "save", "id": persona["id"],
                                      "answer": answer}))
            self.assertEqual(saved["status"], "complete", saved.get("error"))

        tally = run(bi.run_skill(PANEL_PID, "founder-consumer", {},
                                 {"op": "tally"}))
        self.assertEqual(tally["status"], "complete", tally.get("error"))
        self.assertTrue((founder / "panel" / "results.json").is_file())

    def test_pricing_reads_real_answers_and_refuses_missing_ones(self):
        founder = bi.workdir_for(PANEL_PID)
        self.assertTrue((founder / "panel" / "answers").is_dir())
        result = run(bi.run_skill(PANEL_PID, "founder-pricing", {},
                                  {"price": 6.50}))
        self.assertEqual(result["status"], "complete", result.get("error"))
        self.assertIn("6.50", result["content"])

        missing = run(bi.run_skill(PRICING_PID, "founder-pricing", {},
                                   {"price": 6.50}))
        self.assertEqual(missing["status"], "failed")
        self.assertIn("panel answers", missing["error"])
        self.assertEqual(missing["content"], "")

    def test_compile_handles_missing_directory_safely(self):
        result = run(bi.run_skill(910012, "founder-plan", bi.SENTINEL_CONTEXT_TEMPLATE))
        self.assertEqual(result["status"], "complete", result.get("error"))
        self.assertIn("**Verdict:", result["content"])
        self.assertIn("Incomplete", result["content"])


def _panel_reasons():
    """Reason codes the vendored panel accepts (read from the tool itself)."""
    import importlib.util
    path = SKILLS / "founder-consumer" / "panel.py"
    spec = importlib.util.spec_from_file_location("zds_panel", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.REASONS)


class HonestyGateTests(unittest.TestCase):
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


class WorkflowTests(unittest.TestCase):
    def test_full_workflow_produces_a_compiled_plan(self):
        # 1. deterministic prep: a real panel with real answers
        customer = json.loads(EXAMPLE_CUSTOMER.read_text(encoding="utf-8"))
        pitch = EXAMPLE_PITCH.read_text(encoding="utf-8")
        run(bi.run_skill(WORKFLOW_PID, "founder-consumer", {},
                         {"op": "init", "customer": customer,
                          "pitch": pitch, "n": 6}))
        founder = bi.workdir_for(WORKFLOW_PID)
        personas = json.loads((founder / "panel" / "personas.json")
                              .read_text(encoding="utf-8"))
        reason = sorted(_panel_reasons())[0]
        for persona in personas:
            run(bi.run_skill(WORKFLOW_PID, "founder-consumer", {},
                             {"op": "save", "id": persona["id"], "answer": {
                                 "id": persona["id"], "buys": True,
                                 "purchases_first_month": 3,
                                 "reason_code": reason,
                                 "reason": "habit", "objection": "price",
                                 "would_change_my_mind": "",
                                 "price_too_cheap": 3.0, "price_cheap": 5.0,
                                 "price_expensive": 7.0,
                                 "price_too_expensive": 9.0}}))

        # 2. stub the model so the workflow test is deterministic and offline
        async def fake_llm(skill_id, context, inputs, prior, evidence):
            return {"kind": "llm", "status": "complete",
                    "content": f"# {skill_id}\n\nFixture document.",
                    "output": {}, "error": None, "meta": {"generated_by": "llm"}}

        numbers = json.loads(EXAMPLE_NUMBERS.read_text(encoding="utf-8"))
        inputs = {
            "founder-consumer": {"op": "check"},
            "founder-pricing": {"price": 6.50},
            "founder-cfo": {"numbers": numbers},
        }
        stored = {}

        async def fetch_prior(pid):
            return [dict(v, skill_id=k) for k, v in stored.items()]

        async def recorder(skill_id, result):
            stored[skill_id] = result

        original_llm, original_hook = bi._run_llm, None
        bi._run_llm = fake_llm
        bi.set_recorder(recorder)
        try:
            results = run(bi.run_workflow(WORKFLOW_PID,
                                          bi.SENTINEL_CONTEXT_TEMPLATE,
                                          inputs, fetch_prior=fetch_prior))
        finally:
            bi._run_llm = original_llm
            bi.set_recorder(None)

        self.assertEqual(len(results), 11)
        by_id = {r["skill_id"]: r for r in results}
        for skill_id in ("founder-board", "founder-cfo", "founder-pricing",
                         "founder-plan", "founder-marketing"):
            self.assertEqual(by_id[skill_id]["status"], "complete",
                             f"{skill_id}: {by_id[skill_id].get('error')}")
        # competitors honestly stayed gated (no evidence supplied)
        self.assertEqual(by_id["founder-competitors"]["status"], "needs_research")

        plan = by_id["founder-plan"]["content"]
        self.assertIn("**Verdict:", plan)
        self.assertIn("The numbers", plan)
        self.assertIn("4.76", plan)          # real CFO numbers made the plan
        self.assertIn("## Marketing", plan)  # an LLM section made it in
        self.assertIn("Fixture document.", plan)
        self.assertIn("run /founder-competitors", plan)  # honest gap listing


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
        self.assertEqual(len(data["skills"]), 11)
        self.assertNotIn("/Users/", res.text)      # no host file-system paths

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
        self.assertEqual(len(res.json()["skills"]), 11)
        state = self.client.get(f"/business/projects/{pid}").json()
        statuses = {o["skill_id"]: o["status"] for o in state["outputs"]}
        self.assertEqual(len(statuses), 11)
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
