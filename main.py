import json
import os
import re
import time
import asyncio
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
import httpx
from utils import robust_json_parse

# --- LLM Configuration ---
# Using Groq for speed/cost efficiency. Fallback to OpenAI if needed.
llm = ChatOpenAI(
    # Groq retires model ids; GROQ_MODEL overrides without a code change.
    model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    temperature=0.1,
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY")
)

# --- Rate limiting ----------------------------------------------------------
# Groq's free tier meters 8,000 TPM / 200,000 TPD. A burst of concurrent
# scans trips HTTP 429 ("Rate limit reached ... Please try again in 24.615s")
# and every analysis in flight dies with it - which is exactly how the
# landing page's captures were failing. This token bucket keeps all agents
# inside a budget the account really has, run_scan() retries what still gets
# through, and the leads that do fail record why (see api._fail_lead_task).

GROQ_TPM_LIMIT = int(os.getenv("GROQ_TPM_LIMIT", "7500"))   # 0 disables
# Tokens charged per agent call. Groq bills prompt + completion, and the
# observed 429 asked for 3,600 tokens at once, so a token-thin hold (150)
# would throttle nothing. settle() refunds the difference against the usage
# the response actually reports, so the bucket tracks reality over time.
GROQ_CALL_TOKENS = int(os.getenv("GROQ_CALL_TOKEN_ESTIMATE", "1500"))


class GroqRateLimiter:
    """Token bucket every agent must pass before it talks to Groq."""

    def __init__(self, max_tokens_per_minute: int = GROQ_TPM_LIMIT,
                 call_cost: int = GROQ_CALL_TOKENS):
        self.max_tokens = float(max_tokens_per_minute)
        self.call_cost = float(call_cost)
        self.tokens = self.max_tokens
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    def _refill(self) -> None:
        """Credit tokens back for time passed (capped at one minute's budget)."""
        now = time.monotonic()
        self.tokens = min(
            self.max_tokens,
            self.tokens + (now - self.last_refill) * (self.max_tokens / 60.0),
        )
        self.last_refill = now

    async def acquire(self, token_cost: Optional[float] = None) -> float:
        """Hold token budget before an LLM call; wait out an empty minute."""
        if self.max_tokens <= 0:
            return 0.0  # throttling disabled (tests, or a paid tier)
        cost = float(self.call_cost if token_cost is None else token_cost)
        async with self.lock:
            self._refill()
            if self.tokens < cost:
                await asyncio.sleep((cost - self.tokens) / (self.max_tokens / 60.0))
                self._refill()
            self.tokens -= cost
        return cost

    async def settle(self, hold: float, response: Any) -> None:
        """Refund the part of the hold the call did not actually spend."""
        if hold <= 0:
            return
        usage = getattr(response, "usage_metadata", None)
        actual = usage.get("total_tokens") if isinstance(usage, dict) else None
        if not isinstance(actual, (int, float)) or actual >= hold:
            return
        async with self.lock:
            self._refill()
            self.tokens = min(self.max_tokens, self.tokens + (hold - actual))


groq_limiter = GroqRateLimiter()


_RATE_LIMIT_AFTER = re.compile(r"try again in ([\d.]+)s", re.IGNORECASE)


def _is_rate_limit_error(exc: BaseException) -> bool:
    text = str(exc)
    return "429" in text or "rate limit" in text.lower()


def _rate_limit_delay(exc: BaseException, attempt: int) -> float:
    """Groq states the wait exactly ('Please try again in 24.615s'); use it."""
    match = _RATE_LIMIT_AFTER.search(str(exc))
    if match:
        return min(max(float(match.group(1)), 1.0), 120.0)
    return min(30.0 * attempt, 120.0)


# --- State Definition ---
class ScanState(TypedDict):
    domain: str
    raw_scan: Dict
    risk_assessment: List[Dict]
    remediation_plan: List[Dict]
    executive_summary: str
    risk_score: int
    errors: List[str]
    loop_count: int
    client_id: Optional[str] # For DB tracking
    signals: List[str] # Discovery signals (e.g. exposed_api) that prioritize analysis

# --- Agents ---

async def scout(state: ScanState) -> Dict:
    """Agent 1: Executes security scans."""
    domain = state["domain"]
    print(f"[SCOUT] Scanning {domain}...")
    
    # In production, this calls your scanners.py functions
    # Here we simulate a robust scan structure
    raw_data = {
        "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
        "open_ports": [80, 443, 22],
        "tls_issues": ["Weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA"],
        "exposed_services": ["Apache/2.4.41 (Ubuntu)"],
        "dns_records": {"mx": ["mail.example.com"], "spf": "Missing"}
    }
    
    # Simulate tool failure handling
    if "nonexistent-domain-xyz-123.com" in domain:
        return {"raw_scan": {"error": "Domain not found"}}
        
    return {"raw_scan": raw_data}

async def analyst(state: ScanState) -> Dict:
    """Agent 2: Contextualizes raw data into business risk."""
    domain = state["domain"]
    raw_data = state.get("raw_scan", {})
    previous_errors = state.get("errors", [])
    loop_count = state.get("loop_count", 0)
    
    # If this is a retry, we include the critic's feedback in the prompt
    feedback_context = ""
    if previous_errors and loop_count > 0:
        feedback_context = f"\n\nPrevious Critique Feedback:\n{json.dumps(previous_errors)}\nAddress these specific issues in your analysis."

    # Harvey-discovery signals: prioritize findings that confirm them
    signals = state.get("signals") or []
    signals_context = (
        "\n\nExternally observed signals (independently confirmed during discovery): "
        + ", ".join(signals)
        + ". Prioritize findings that confirm these signals."
        if signals else ""
    )

    prompt = ChatPromptTemplate.from_template("""
    You are a CISO. Analyze this security scan data for {domain}.
    
    Raw Data:
    {raw_data}
    
    Identify the top 3 business risks. Do not list every bug. Focus on:
    1. Data Exposure (PII, Keys, Admin Panels).
    2. Brand Reputational Risk (Phishing, Spoofing).
    3. Operational Disruption (DDoS, Misconfig).
    
    Return JSON ONLY in this format:
    {{
      "risks": [
        {{
          "id": 1,
          "title": "Short Title",
          "severity": "Critical|High|Medium|Low",
          "business_impact": "One sentence on money/reputation impact",
          "technical_detail": "Technical explanation"
        }}
      ]
    }}
    {feedback_context}{signals_context}
    """)
    
    messages = prompt.format(
        domain=domain,
        raw_data=json.dumps(raw_data),
        feedback_context=feedback_context,
        signals_context=signals_context,
    )
    hold = await groq_limiter.acquire()
    response = await llm.ainvoke(messages)
    await groq_limiter.settle(hold, response)
    
    # Use Robust JSON Parser from utils
    parsed = robust_json_parse(response.content)
    
    # Validate Structure
    if "risks" not in parsed:
        parsed = {"risks": []}
        
    return {"risk_assessment": parsed["risks"], "loop_count": loop_count + 1}

async def fixer(state: ScanState) -> Dict:
    """Agent 3: Provides actionable fixes."""
    domain = state["domain"]
    risks = state.get("risk_assessment", [])
    
    if not risks:
        return {"remediation_plan": []}

    prompt = ChatPromptTemplate.from_template("""
    You are a Senior Security Engineer. 
    Domain: {domain}
    Risks: {risks}
    
    Provide a step-by-step remediation plan for each risk. 
    - Be specific. Use code snippets for config files.
    - Assume the user is a mid-level developer.
    
    Return JSON ONLY:
    {{
      "fixes": [
        {{
          "risk_id": 1,
          "steps": ["Step 1", "Step 2"],
          "code_snippet": "code here if applicable"
        }}
      ]
    }}
    """)
    
    messages = prompt.format(domain=domain, risks=json.dumps(risks))
    hold = await groq_limiter.acquire()
    response = await llm.ainvoke(messages)
    await groq_limiter.settle(hold, response)
    
    parsed = robust_json_parse(response.content)
    if "fixes" not in parsed:
        parsed = {"fixes": []}
        
    return {"remediation_plan": parsed["fixes"]}

async def editor(state: ScanState) -> Dict:
    """Agent 4: Generates summary and score."""
    domain = state["domain"]
    risks = state.get("risk_assessment", [])
    
    # Calculate Score
    score = 100
    for risk in risks:
        if risk.get("severity") == "Critical":
            score -= 20
        elif risk.get("severity") == "High":
            score -= 10
        elif risk.get("severity") == "Medium":
            score -= 5
    score = max(0, score)

    # Harvey-discovery signals: the summary must reference the specific signal
    signals = state.get("signals") or []
    signals_context = (
        "    Independently observed signals: " + ", ".join(signals) + ".\n"
        "    If a top risk connects to one of these signals, say so explicitly "
        "(e.g. 'Given your public API, this exposure is high-risk').\n"
        if signals else ""
    )

    prompt = ChatPromptTemplate.from_template("""
    Write a 150-word executive summary for {domain}.
    Current Risk Score: {score}/100.
    Top Risks: {risks}
    
    Tone: Confident, authoritative, concise. No jargon, no hype.
    End with a call to action: 'Keep your business safe with Zero-Trust Sentinel.'
{signals_context}    Return plain text only.
    """)
    
    messages = prompt.format(
        domain=domain, score=score, risks=json.dumps(risks), signals_context=signals_context,
    )
    hold = await groq_limiter.acquire()
    response = await llm.ainvoke(messages)
    await groq_limiter.settle(hold, response)
    
    return {"executive_summary": response.content, "risk_score": score}

async def critic(state: ScanState) -> Dict:
    """Agent 5: Validates output."""
    domain = state["domain"]
    summary = state.get("executive_summary", "")
    risks = state.get("risk_assessment", [])
    fixes = state.get("remediation_plan", [])
    raw_data = state.get("raw_scan", {})
    
    prompt = ChatPromptTemplate.from_template("""
    You are a Quality Assurance Agent for a security report.
    
    Domain: {domain}
    Raw Data (Source of Truth): {raw_data}
    Executive Summary: {summary}
    Risks: {risks}
    Fixes: {fixes}
    
    Check for:
    1. Hallucinations: Does the report mention vulnerabilities NOT present in the Raw Data?
    2. Tone: Is it too technical for a business owner?
    3. Completeness: Are all Critical risks addressed in the fixes?
    
    Return JSON ONLY:
    {{
      "errors": ["Error description 1", "Error description 2"],
      "suggestions": ["Suggestion 1"]
    }}
    If no errors, return empty lists.
    """)
    
    messages = prompt.format(
        domain=domain, 
        raw_data=json.dumps(raw_data),
        summary=summary,
        risks=json.dumps(risks),
        fixes=json.dumps(fixes)
    )
    hold = await groq_limiter.acquire()
    response = await llm.ainvoke(messages)
    await groq_limiter.settle(hold, response)
    
    parsed = robust_json_parse(response.content)
    if "errors" not in parsed:
        parsed = {"errors": []}
        
    return {"errors": parsed["errors"]}

# --- Graph Construction ---

def should_continue(state: ScanState) -> str:
    """Conditional Edge Logic."""
    if state.get("errors") and state.get("loop_count", 0) < 3:
        return "analyst" # Loop back to Analyst with feedback
    return "end"

workflow = StateGraph(ScanState)

workflow.add_node("scout", scout)
workflow.add_node("analyst", analyst)
workflow.add_node("fixer", fixer)
workflow.add_node("editor", editor)
workflow.add_node("critic", critic)

workflow.set_entry_point("scout")
workflow.add_edge("scout", "analyst")
workflow.add_edge("analyst", "fixer")
workflow.add_edge("fixer", "editor")
workflow.add_edge("editor", "critic")

workflow.add_conditional_edges(
    "critic",
    should_continue,
    {
        "analyst": "analyst",
        "end": END
    }
)

app = workflow.compile()

# --- Execution Function ---
async def run_scan(domain: str, client_id: str = None, signals: List[str] = None,
                   max_retries: int = 3) -> Dict:
    """Entry point for the scanning process.

    signals: optional discovery signals (e.g. ["exposed_api"]) that the Analyst
    and Editor prioritize and reference in the executive summary.
    max_retries: attempts on Groq 429 (each waits out Groq's stated delay).
    """
    initial_state = {
        "domain": domain,
        "raw_scan": {},
        "risk_assessment": [],
        "remediation_plan": [],
        "executive_summary": "",
        "risk_score": 100,
        "errors": [],
        "loop_count": 0,
        "client_id": client_id,
        "signals": signals or [],
    }

    # Run the graph, retrying only on Groq's rate limit: the free tier meters
    # per minute and per day, so the scans that lose a burst's race get a 429
    # while their siblings succeed. Anything else still raises immediately.
    final_state: Optional[Dict] = None
    for attempt in range(1, max_retries + 1):
        try:
            final_state = await app.ainvoke(initial_state)
            break
        except Exception as e:
            if attempt >= max_retries or not _is_rate_limit_error(e):
                raise
            delay = _rate_limit_delay(e, attempt)
            print(f"[RATE LIMIT] Groq 429 for {domain}; "
                  f"retry {attempt}/{max_retries - 1} in {delay:.1f}s")
            await asyncio.sleep(delay)
    if final_state is None:
        raise RuntimeError(f"run_scan produced no result for {domain}")

    
    # Post-processing: Save to DB (Simulated here)
    if final_state.get("risk_score", 100) < 80:
        print(f"[SUCCESS] High-risk lead identified: {domain} (Score: {final_state['risk_score']})")
    else:
        print(f"[INFO] Low-risk domain: {domain} (Score: {final_state['risk_score']})")
        
    return final_state

if __name__ == "__main__":
    # Test the engine
    asyncio.run(run_scan("example.com"))