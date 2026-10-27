"""Sentinel Business Intelligence - founder-skill integration.

Wraps the eleven MIT-licensed skills vendored in ``vendor/founder-skill`` and
exposes them to the FastAPI app as three honest capability classes:

    tool      deterministic, standard-library scripts (no network, no model)
    llm       instruction-driven skills interpreted by the existing Groq
              adapter (main.llm) behind the existing GroqRateLimiter
    research  needs verifiable external sources; without supplied evidence the
              run stops with ``needs_research`` instead of inventing facts

Design rules (Section 4 of the integration spec):

* The model never chooses commands. Tool invocations are fixed argv lists
  built from the registry below - never a shell, never model-provided paths.
* Model failure (missing key, exhausted quota, timeout) is recorded as a
  structured error. It is never replaced by generated content.
* Research skills refuse to run without ``inputs.evidence`` (URLs/sources the
  user supplied). No fabricated competitors, prices or citations.
* The Groq rate limiter, 429 retry policy and timeouts from main.py are
  reused, so business analysis shares the scan budget instead of starving it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from main import (
    LLM_CONFIGURED,
    _is_rate_limit_error,
    _rate_limit_delay,
    groq_limiter,
    llm,
)

REPO_ROOT = Path(__file__).resolve().parent
VENDOR_SKILLS = REPO_ROOT / "vendor" / "founder-skill" / "skills"
WORK_ROOT = Path(os.getenv("BUSINESS_WORK_DIR", str(REPO_ROOT / "business_work")))

TOOL_TIMEOUT_SECONDS = int(os.getenv("BUSINESS_TOOL_TIMEOUT", "90"))
LLM_TIMEOUT_SECONDS = int(os.getenv("BUSINESS_LLM_TIMEOUT", "120"))
LLM_MAX_RETRIES = 3
MAX_INPUT_BYTES = int(os.getenv("BUSINESS_MAX_INPUT_BYTES", "50000"))
MAX_CONTEXT_BYTES = int(os.getenv("BUSINESS_MAX_CONTEXT_BYTES", "50000"))

# Files compile.py assembles, in document order: skill id -> file inside founder/
PLAN_SECTION_FILES = [
    ("founder-board", "board.md"),
    ("founder-competitors", "competitors.md"),
    ("founder-consumer", "panel/results.md"),
    ("founder-pricing", "pricing.md"),
    ("founder-offer", "offer.md"),
    ("founder-cfo", "cfo.md"),
    ("founder-marketing", "marketing.md"),
    ("founder-brand", "brand.md"),
    ("founder-ops", "ops.md"),
    ("founder-launch", "launch.md"),
]

# The canonical order from the upstream README.
WORKFLOW_ORDER = [
    "founder-board",
    "founder-competitors",
    "founder-consumer",
    "founder-pricing",
    "founder-offer",
    "founder-cfo",
    "founder-marketing",
    "founder-brand",
    "founder-ops",
    "founder-launch",
    "founder-plan",
]

SKILLS: Dict[str, Dict[str, Any]] = {
    "founder-board": {
        "title": "Board of Directors",
        "kind": "llm",
        "requires_research": False,
        "summary": "Three board members apply published frameworks, score the "
                   "business, name what would kill it and vote.",
    },
    "founder-competitors": {
        "title": "Competitor Scout",
        "kind": "research",
        "requires_research": True,
        "summary": "Maps competitors from public sources with links. Requires "
                   "supplied evidence - no evidence, no output.",
    },
    "founder-consumer": {
        "title": "Buyer Panel",
        "kind": "tool",
        "requires_research": False,
        "summary": "Deterministic persona dealing, answer validation and "
                   "tallying (panel.py).",
        "tool": {"script": "founder-consumer/panel.py",
                 "ops": ["init", "prompts", "check", "save", "tally", "status"]},
    },
    "founder-pricing": {
        "title": "Pricing Strategist",
        "kind": "tool",
        "requires_research": False,
        "summary": "Van Westendorp price range from panel answers or a survey "
                   "CSV (van_westendorp.py).",
        "tool": {"script": "founder-pricing/van_westendorp.py"},
    },
    "founder-offer": {
        "title": "Offer Architect",
        "kind": "llm",
        "requires_research": False,
        "summary": "Builds the offer stack that answers the panel's top "
                   "objections.",
    },
    "founder-cfo": {
        "title": "CFO",
        "kind": "tool",
        "requires_research": False,
        "summary": "Unit economics: contribution, break-even, year-1 months, "
                   "cash and payback (unit_economics.py).",
        "tool": {"script": "founder-cfo/unit_economics.py"},
    },
    "founder-marketing": {
        "title": "Marketing Director",
        "kind": "llm",
        "requires_research": False,
        "summary": "Positioning, channels, a dated 30-day campaign and the "
                   "maximum payback-safe acquisition cost.",
    },
    "founder-brand": {
        "title": "Brand Designer",
        "kind": "llm",
        "requires_research": False,
        "summary": "Name candidates, voice, promise and a look brief "
                   "(checks to run, not claims to make).",
    },
    "founder-ops": {
        "title": "Operations Manager",
        "kind": "llm",
        "requires_research": False,
        "summary": "Suppliers, routines, tools, permits to check and a risk "
                   "register feeding real costs back to the CFO.",
    },
    "founder-launch": {
        "title": "Launch Lead",
        "kind": "llm",
        "requires_research": False,
        "summary": "A cheap real-world test first, then a dated countdown and "
                   "run sheet.",
    },
    "founder-plan": {
        "title": "Business Planner",
        "kind": "tool",
        "requires_research": False,
        "summary": "Compiles every prior output into one plan with a computed "
                   "verdict (compile.py).",
        "tool": {"script": "founder-plan/compile.py"},
    },
}

# Facts about Sentinel itself that come from this repository. Nothing here is
# revenue, conversion or customer data - those stay null until supplied.
SENTINEL_CONTEXT_TEMPLATE: Dict[str, Any] = {
    "product": {
        "name": "Zero-Trust Sentinel",
        "one_liner": "Automated external attack-surface discovery and "
                     "evidence-based security reporting for SMBs.",
        "capabilities": [
            "Automated external attack-surface discovery (subdomains, live "
            "hosts, TLS/certificate inspection)",
            "Authorized public-domain security assessment with preflight "
            "target validation and DNS fast-fail",
            "Evidence-based reporting with business-impact translation",
            "Actionable, prioritized remediation recommendations",
            "Security assessment subscriptions (monthly/annual)",
            "Ethical, permission-based customer acquisition: outbound only "
            "to leads that match discovery signals, with suppression and "
            "unsubscribe handling",
        ],
    },
    "delivery": {
        "stack": "FastAPI + LangGraph + PostgreSQL + Docker",
        "hosting_target": "Oracle Cloud Always Free VM (zero recurring cost)",
        "scanner_tools": ["subfinder", "httpx", "nuclei", "testssl.sh"],
    },
    "costs": {
        "llm": "Groq free tier: 7,500 tokens/min token bucket, 200,000 "
               "tokens/day observed cap; 429s retried with server-stated delay",
        "email_provider": "Resend/SendGrid free tiers (sending currently "
                          "gated: sender domain authorization pending)",
        "hosting": "0 USD/month target (Oracle Always Free + Cloudflare DNS)",
        "notes": "Fill variable costs in from real invoices; leave unknown "
                 "values null rather than estimating.",
    },
    "metrics": {
        "customers": None,
        "mrr": None,
        "conversion_rate": None,
        "churn_rate_monthly": None,
        "cac": None,
        "notes": "Deliberately empty. Supply real numbers or leave null - the "
                 "CFO tool errors on missing fields instead of guessing.",
    },
    "constraints": [
        "No paid LLM, hosting or database dependency may be introduced",
        "No invented customers, revenue, reviews, citations or testimonials",
        "Panel/simulation output is hypothesis, never forecast or testimonial",
    ],
}


class SkillInputError(ValueError):
    """Raised for malformed or oversized user input."""


class SkillUnavailable(RuntimeError):
    """Raised when a capability genuinely cannot run (honest failure)."""


def get_registry() -> List[Dict[str, Any]]:
    """Public skill registry - no paths outside the vendor tree, no secrets."""
    out = []
    for skill_id in WORKFLOW_ORDER:
        spec = SKILLS[skill_id]
        out.append({
            "id": skill_id,
            "title": spec["title"],
            "kind": spec["kind"],
            "requires_research": spec["requires_research"],
            "summary": spec["summary"],
            "operations": spec.get("tool", {}).get("ops", []),
        })
    return out


def validate_skill_id(skill_id: str) -> Dict[str, Any]:
    if not isinstance(skill_id, str) or skill_id not in SKILLS:
        raise SkillInputError(f"unknown skill '{skill_id}'")
    return SKILLS[skill_id]


def _check_size(payload: Any, limit: int, label: str) -> None:
    try:
        raw = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise SkillInputError(f"{label} is not serializable: {exc}") from exc
    if len(raw.encode("utf-8")) > limit:
        raise SkillInputError(f"{label} exceeds {limit} bytes")


def workdir_for(project_id: int) -> Path:
    """Project workdir, constrained to an integer id (no traversal)."""
    try:
        pid = int(project_id)
    except (TypeError, ValueError) as exc:
        raise SkillInputError("project_id must be an integer") from exc
    if pid < 1:
        raise SkillInputError("project_id must be positive")
    path = WORK_ROOT / str(pid) / "founder"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _script_path(skill_id: str) -> Path:
    """Resolve a registry script inside the vendored tree, or refuse."""
    rel = SKILLS[skill_id].get("tool", {}).get("script")
    if not rel:
        raise SkillUnavailable(f"{skill_id} has no deterministic tool")
    script = (VENDOR_SKILLS / rel).resolve()
    if VENDOR_SKILLS.resolve() not in script.parents or script.suffix != ".py":
        raise SkillUnavailable("registry script escapes the vendored tree")
    if not script.is_file():
        raise SkillUnavailable(f"vendored tool missing: {rel}")
    return script


def _skill_md(skill_id: str) -> str:
    path = VENDOR_SKILLS / skill_id / "SKILL.md"
    if not path.is_file():
        raise SkillUnavailable(f"SKILL.md missing for {skill_id}")
    # Bounded read: prompts must not grow without limit.
    return path.read_text(encoding="utf-8")[:12000]


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def _exec(argv: List[str], cwd: Path,
                 stdin_text: Optional[str] = None) -> Dict[str, Any]:
    """Run one vendored script. Fixed argv, no shell, bounded time/output."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        payload = stdin_text.encode("utf-8") if stdin_text is not None else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=payload), timeout=TOOL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        raise SkillUnavailable(
            f"tool timed out after {TOOL_TIMEOUT_SECONDS}s") from exc
    except FileNotFoundError as exc:
        raise SkillUnavailable(f"interpreter not found: {argv[0]}") from exc

    out = stdout.decode("utf-8", "replace")
    err = stderr.decode("utf-8", "replace")
    return {"rc": proc.returncode, "stdout": out, "stderr": err}


# ---------------------------------------------------------------------------
# Deterministic tools
# ---------------------------------------------------------------------------

async def _run_tool(skill_id: str, project_id: int, inputs: Dict[str, Any]) -> Dict[str, Any]:
    founder = workdir_for(project_id)
    script = _script_path(skill_id)
    py = sys.executable or "python3"
    meta: Dict[str, Any] = {"tool": script.name, "argv_kind": "fixed"}
    content = ""
    artifacts: List[str] = []

    if skill_id == "founder-cfo":
        numbers = inputs.get("numbers")
        if not isinstance(numbers, dict):
            raise SkillInputError(
                "founder-cfo requires inputs.numbers (the numbers.json object)")
        _check_size(numbers, MAX_INPUT_BYTES, "inputs.numbers")
        _write_json(founder / "numbers.json", numbers)
        res = await _exec([py, str(script), "numbers.json", "--out", "cfo.md"],
                          cwd=founder)
        if res["rc"] != 0:
            raise SkillUnavailable(
                "unit economics rejected the inputs: "
                + (res["stderr"] or res["stdout"]).strip()[:500])
        content = (founder / "cfo.md").read_text(encoding="utf-8")
        artifacts.append("founder/cfo.md")

    elif skill_id == "founder-consumer":
        op = str(inputs.get("op", "status"))
        if op not in SKILLS[skill_id]["tool"]["ops"]:
            raise SkillInputError(
                f"op must be one of {SKILLS[skill_id]['tool']['ops']}")
        panel_dir = "panel"
        if op == "init":
            customer = inputs.get("customer")
            pitch = inputs.get("pitch")
            if not isinstance(customer, dict) or not isinstance(pitch, str):
                raise SkillInputError(
                    "panel init requires inputs.customer (object) and "
                    "inputs.pitch (string)")
            _check_size(customer, MAX_INPUT_BYTES, "inputs.customer")
            _check_size(pitch, MAX_INPUT_BYTES, "inputs.pitch")
            _write_json(founder / "customer.json", customer)
            (founder / "pitch.md").write_text(pitch, encoding="utf-8")
            n = inputs.get("n", 100)
            if not isinstance(n, int) or not (1 <= n <= 500):
                raise SkillInputError("n must be an integer between 1 and 500")
            argv = [py, str(script), "--dir", panel_dir, "init",
                    "--customer", "customer.json", "--pitch", "pitch.md",
                    "--n", str(n)]
            res = await _exec(argv, cwd=founder)
            if res["rc"] != 0:
                raise SkillUnavailable(
                    "panel init failed: " + res["stderr"].strip()[:500])
            content = res["stdout"].strip() or "panel initialised"
            artifacts.append("founder/panel/")
        elif op == "save":
            buyer_id = inputs.get("id")
            answer = inputs.get("answer")
            if not isinstance(buyer_id, str) or not isinstance(answer, (dict, str)):
                raise SkillInputError(
                    "panel save requires inputs.id (buyer id string) and "
                    "inputs.answer (object or markdown string)")
            if not buyer_id.replace("-", "").replace("_", "").isalnum():
                raise SkillInputError("buyer id must be alphanumeric")
            _check_size(answer, MAX_INPUT_BYTES, "inputs.answer")
            text = answer if isinstance(answer, str) else json.dumps(answer)
            res = await _exec(
                [py, str(script), "--dir", panel_dir, "save", buyer_id],
                cwd=founder, stdin_text=text)
            if res["rc"] != 0:
                raise SkillUnavailable(
                    "panel save failed: " + res["stderr"].strip()[:500])
            content = res["stdout"].strip() or f"saved answer for {buyer_id}"
        else:  # check / tally / status
            argv = [py, str(script), "--dir", panel_dir, op]
            if op == "tally" and inputs.get("out"):
                out_name = str(inputs["out"])
                if "/" in out_name or ".." in out_name:
                    raise SkillInputError("out must be a plain file name")
                argv += ["--out", out_name]
            res = await _exec(argv, cwd=founder)
            if res["rc"] != 0:
                raise SkillUnavailable(
                    f"panel {op} failed (no answers yet?): "
                    + (res["stderr"] or res["stdout"]).strip()[:500])
            content = res["stdout"].strip() or res["stderr"].strip()

    elif skill_id == "founder-pricing":
        price = inputs.get("price")
        argv = [py, str(script)]
        source = inputs.get("source", "panel/answers")
        if isinstance(source, str) and ("/" not in source or ".." not in source):
            src_path = founder / source
        else:
            raise SkillInputError("source must be a relative path under founder/")
        if not src_path.exists():
            raise SkillInputError(
                "no panel answers found - run founder-consumer first or "
                "supply inputs.source pointing at a survey folder/CSV")
        argv.append(str(source))
        if price is not None:
            try:
                argv += ["--price", str(float(price))]
            except (TypeError, ValueError) as exc:
                raise SkillInputError("price must be a number") from exc
        argv += ["--out", "pricing.md"]
        res = await _exec(argv, cwd=founder)
        if res["rc"] != 0:
            raise SkillUnavailable(
                "pricing analysis failed: "
                + (res["stderr"] or res["stdout"]).strip()[:500])
        content = (founder / "pricing.md").read_text(encoding="utf-8")
        artifacts.append("founder/pricing.md")

    elif skill_id == "founder-plan":
        # Materialise every completed prior output where compile.py expects it.
        for prior in inputs.get("_prior", []):
            pid_file = dict(PLAN_SECTION_FILES).get(prior.get("skill_id"))
            if not pid_file or not prior.get("content"):
                continue
            target = founder / pid_file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(prior["content"]), encoding="utf-8")
            if prior.get("skill_id") == "founder-board":
                # compile.py reads founder/idea.md for the plan's title.
                (founder / "idea.md").write_text(
                    str(prior["content"]), encoding="utf-8")
        res = await _exec([py, str(script), "--dir", "."], cwd=founder)
        if res["rc"] != 0:
            raise SkillUnavailable(
                "plan compilation failed: "
                + (res["stderr"] or res["stdout"]).strip()[:500])
        plan_path = founder / "business-plan.md"
        if not plan_path.is_file():
            raise SkillUnavailable("compiler produced no business-plan.md")
        content = plan_path.read_text(encoding="utf-8")
        artifacts.append("founder/business-plan.md")
        meta["verdict"] = next(
            (l.split("**", 2)[1].split(": ", 1)[1]
             for l in content.splitlines()[:6] if l.startswith("**Verdict")),
            "unknown")
    else:  # pragma: no cover - registry and branch list are in sync
        raise SkillUnavailable(f"{skill_id} has no tool implementation")

    meta["artifacts"] = artifacts
    return {"kind": "tool", "status": "complete", "content": content,
            "output": {"artifacts": artifacts}, "error": None, "meta": meta}


# ---------------------------------------------------------------------------
# Instruction-driven skills (existing Groq adapter + rate limiter)
# ---------------------------------------------------------------------------

def _research_evidence(inputs: Dict[str, Any]) -> List[Dict[str, str]]:
    evidence = inputs.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return []
    clean = []
    for item in evidence[:25]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()[:500]
        note = str(item.get("note", "")).strip()[:500]
        if url or note:
            clean.append({"url": url, "note": note})
    return clean


def build_prompt(skill_id: str, context: Dict[str, Any],
                 inputs: Dict[str, Any], prior: List[Dict[str, Any]],
                 evidence: List[Dict[str, str]]) -> str:
    skill_md = _skill_md(skill_id)
    prior_text = "\n\n".join(
        f"## {p.get('skill_id')}\n{str(p.get('content'))[:4000]}"
        for p in prior if p.get("content")) or "(none yet)"
    evidence_text = "\n".join(
        f"- {e['url']} {e['note']}".strip() for e in evidence) or "(none)"
    user_bits = ""
    if inputs:
        _check_size(inputs, MAX_INPUT_BYTES, "inputs")
        user_bits = f"\nExtra inputs for this run:\n{json.dumps(inputs)[:6000]}\n"
    return f"""You are one capability inside Zero-Trust Sentinel's business
intelligence module. Apply the skill instructions below to THIS business.

=== SKILL INSTRUCTIONS (upstream founder-skill, MIT) ===
{skill_md}

=== BUSINESS CONTEXT ===
{json.dumps(context, indent=2, default=str)[:12000]}
{user_bits}
=== WHAT THE OTHER SKILLS ALREADY PRODUCED ===
{prior_text}

=== VERIFIABLE EVIDENCE SUPPLIED FOR THIS RUN ===
{evidence_text}

HARD RULES:
- Never invent customers, revenue, conversion rates, prices, reviews,
  citations, testimonials or supplier quotes. Every fact must come from the
  context, the evidence list, or the prior outputs above.
- Mark every estimate explicitly as an estimate and say what would confirm it.
- Simulated buyer panels are hypotheses, not forecasts or testimonials.
- If you cannot do something without external research, say exactly what is
  missing instead of producing plausible content.
- Output one markdown document with a single H1 heading. No preamble."""


async def _run_llm(skill_id: str, context: Dict[str, Any],
                   inputs: Dict[str, Any], prior: List[Dict[str, Any]],
                   evidence: List[Dict[str, str]]) -> Dict[str, Any]:
    _check_size(context, MAX_CONTEXT_BYTES, "context")
    if not LLM_CONFIGURED:
        # Honest failure first: no key means no model, and an unconfigured
        # model must never be replaced by invented content.
        raise SkillUnavailable(
            "model_unavailable: GROQ_API_KEY is not set in this environment")
    prompt = build_prompt(skill_id, context, inputs, prior, evidence)
    last_error: Optional[BaseException] = None

    last_error: Optional[BaseException] = None
    for attempt in range(1, LLM_MAX_RETRIES + 1):
        response = None
        attempt_error: Optional[BaseException] = None
        hold = await groq_limiter.acquire()
        try:
            response = await asyncio.wait_for(
                llm.ainvoke(prompt), timeout=LLM_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 - recorded, never swallowed
            attempt_error = exc
        finally:
            # settle() refunds the unused part of the hold; a failed call has
            # no usage metadata, so the hold simply stays spent.
            if response is not None:
                await groq_limiter.settle(hold, response)

        if attempt_error is None:
            text = (getattr(response, "content", "") or "").strip()
            if text:
                return {
                    "kind": "llm", "status": "complete", "content": text,
                    "output": {}, "error": None,
                    "meta": {
                        "model": getattr(llm, "model", "unknown"),
                        "generated_by": "llm",
                        "attempts": attempt,
                        "assumptions": "AI-generated from the supplied context; "
                                       "verify before acting.",
                    },
                }
            attempt_error = SkillUnavailable("model returned an empty document")

        last_error = attempt_error
        if attempt >= LLM_MAX_RETRIES or not _is_rate_limit_error(attempt_error):
            break
        delay = _rate_limit_delay(attempt_error, attempt)
        print(f"[BIZ] Groq 429 for {skill_id}; retry "
              f"{attempt}/{LLM_MAX_RETRIES - 1} in {delay:.1f}s")
        await asyncio.sleep(delay)

    text = str(last_error)
    if _is_rate_limit_error(last_error):
        reason = "model_rate_limited"
    elif "Missing credentials" in text or "api_key" in text.lower():
        reason = "model_unavailable"
    elif isinstance(last_error, asyncio.TimeoutError):
        reason = "model_timeout"
    else:
        reason = "model_error"
    raise SkillUnavailable(f"{reason}: {text[:400]}")


# ---------------------------------------------------------------------------
# Entry point used by the API layer
# ---------------------------------------------------------------------------

async def run_skill(project_id: int, skill_id: str,
                    context: Dict[str, Any],
                    inputs: Optional[Dict[str, Any]] = None,
                    prior: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Execute one skill and return the record shape db.save_business_output takes."""
    spec = validate_skill_id(skill_id)
    inputs = inputs or {}
    prior = prior or []
    if not isinstance(inputs, dict):
        raise SkillInputError("inputs must be an object")
    _check_size(inputs, MAX_INPUT_BYTES, "inputs")

    evidence = _research_evidence(inputs)
    if spec["requires_research"] and not evidence:
        return {
            "kind": spec["kind"], "status": "needs_research",
            "content": "",
            "output": {"required": ["verifiable public sources with URLs"]},
            "error": "research skills refuse to run without supplied evidence; "
                     "post evidence=[{url, note}] to continue",
            "meta": {"evidence_status": "missing"},
        }

    try:
        if spec["kind"] == "tool":
            if skill_id == "founder-plan":
                inputs = dict(inputs, _prior=prior)
            return await _run_tool(skill_id, project_id, inputs)
        result = await _run_llm(skill_id, context, inputs, prior, evidence)
        if evidence:
            result["meta"]["evidence_status"] = "supplied_by_user"
        return result
    except SkillInputError as exc:
        return {"kind": spec["kind"], "status": "failed", "content": "",
                "output": {}, "error": f"invalid_input: {exc}", "meta": {}}
    except SkillUnavailable as exc:
        return {"kind": spec["kind"], "status": "failed", "content": "",
                "output": {}, "error": str(exc), "meta": {}}
    except Exception as exc:  # noqa: BLE001 - persist, never crash the task
        return {"kind": spec["kind"], "status": "failed", "content": "",
                "output": {}, "error": f"unexpected: {type(exc).__name__}: {exc}",
                "meta": {}}


async def run_workflow(project_id: int, context: Dict[str, Any],
                       inputs_by_skill: Optional[Dict[str, Dict[str, Any]]] = None,
                       fetch_prior=None) -> List[Dict[str, Any]]:
    """Run all eleven skills in upstream order, recording every outcome.

    Failures do not abort the workflow: each skill's status is recorded and
    the plan compiler still assembles whatever completed.
    """
    inputs_by_skill = inputs_by_skill or {}
    results: List[Dict[str, Any]] = []
    for skill_id in WORKFLOW_ORDER:
        prior = await fetch_prior(project_id) if fetch_prior else []
        result = await run_skill(
            project_id, skill_id, context,
            inputs=inputs_by_skill.get(skill_id, {}), prior=prior)
        result["skill_id"] = skill_id
        results.append(result)
        await _record(skill_id, result)
    return results


async def _record(skill_id: str, result: Dict[str, Any]) -> None:
    """Persist through the db hook installed by the API layer (test seam)."""
    hook = _RECORD_HOOK
    if hook is not None:
        await hook(skill_id, result)


# The API layer installs a persister so this module stays importable without
# a database (tests import it directly).
_RECORD_HOOK = None


def set_recorder(fn) -> None:
    global _RECORD_HOOK
    _RECORD_HOOK = fn


def context_fingerprint(context: Dict[str, Any]) -> str:
    """Stable hash so reports can state which inputs informed them."""
    raw = json.dumps(context, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]
