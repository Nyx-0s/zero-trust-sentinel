"""Sentinel Business Intelligence - the business cockpit's own skills.

Eight analysis capabilities exposed to the FastAPI app as two honest
capability classes:

    llm       instruction-driven skills interpreted by the existing Groq
              adapter (main.llm) behind the existing GroqRateLimiter
    research  needs verifiable external sources; without supplied evidence the
              run stops with ``needs_research`` instead of inventing facts

The instructions in ``SKILL_INSTRUCTIONS`` are written in this repository.
They were shaped by studying an external founder playbook as an ANALYSIS
framework (offer, ICP, pricing, positioning, operations, launch), but no code
from that project is vendored, copied or depended on here - it is not part of
this product.

Design rules:

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
WORK_ROOT = Path(os.getenv("BUSINESS_WORK_DIR", str(REPO_ROOT / "business_work")))

LLM_TIMEOUT_SECONDS = int(os.getenv("BUSINESS_LLM_TIMEOUT", "120"))
LLM_MAX_RETRIES = 3
MAX_INPUT_BYTES = int(os.getenv("BUSINESS_MAX_INPUT_BYTES", "50000"))
MAX_CONTEXT_BYTES = int(os.getenv("BUSINESS_MAX_CONTEXT_BYTES", "50000"))


# The canonical order the workflow runs in.
WORKFLOW_ORDER = [
    "founder-board",
    "founder-competitors",
    "founder-pricing",
    "founder-offer",
    "founder-marketing",
    "founder-brand",
    "founder-ops",
    "founder-launch",
]

# Instructions are authored in this repository - see the module docstring.
SKILL_INSTRUCTIONS: Dict[str, str] = {
    "founder-board": (
        "Score this business the way an unpaid board would: three members "
        "with different biases (operator, customer, skeptic). Each names the "
        "one thing that would kill the company in the next two quarters, the "
        "evidence for it, and a vote (proceed / change course / stop). Weigh "
        "facts from the context above; flag anything you assumed."),
    "founder-competitors": (
        "Map the competitive set strictly from the supplied evidence: for "
        "each competitor state who they serve, their price or business "
        "model, their strongest claim, and the gap this business can own. "
        "Never name a competitor that is not in the evidence list, and never "
        "quote a price that is not cited."),
    "founder-pricing": (
        "Derive a defensible price from willingness-to-pay signals in the "
        "context and the value delivered (hours saved, risk reduced, money "
        "protected). Give a good/better/best structure, the floor price "
        "below which the offer is uneconomic, and say explicitly which "
        "assumption would change the answer."),
    "founder-offer": (
        "Write the offer a stranger can act on in one sentence: who it is "
        "for, what they get, how fast, at what price, with what risk "
        "reversal. Then answer the top objections a sceptical buyer raises "
        "with evidence from the context, not adjectives."),
    "founder-marketing": (
        "Choose positioning, two channels maximum, and a dated 30-day "
        "campaign with an owner and a number per day. Cap the allowed "
        "acquisition cost at what the unit economics in the context can "
        "actually pay back; say so when the context has no economics yet."),
    "founder-brand": (
        "Name candidates, voice, promise and a look brief for this business. "
        "Every name claim must be checkable (a test to run, not an adjective "
        "to assert); include one sentence on what the brand must never say."),
    "founder-ops": (
        "Describe how the work actually runs: suppliers and tools with real "
        "costs from the context, the weekly routine, the permits or "
        "compliance checks that apply, and a risk register where each risk "
        "has an owner and a trigger. Leave costs null when the context does "
        "not state them."),
    "founder-launch": (
        "Design the cheapest real-world test first (what it proves, what it "
        "costs, how long it runs), then a dated countdown and run sheet for "
        "the launch itself: every step, its owner, and the metric that says "
        "the launch worked or must stop."),
}

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
    "founder-pricing": {
        "title": "Pricing Strategist",
        "kind": "llm",
        "requires_research": False,
        "summary": "Good/better/best structure, willingness-to-pay reasoning "
                   "and the floor price below which the offer is uneconomic.",
    },
    "founder-offer": {
        "title": "Offer Architect",
        "kind": "llm",
        "requires_research": False,
        "summary": "Builds the offer stack that answers the panel's top "
                   "objections.",
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
    skill_md = SKILL_INSTRUCTIONS.get(skill_id, "").strip()
    if not skill_md:
        raise SkillUnavailable(f"no instructions authored for {skill_id}")
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
