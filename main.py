import json
import os
import asyncio
from typing import TypedDict, List, Dict, Optional
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
    response = await llm.ainvoke(messages)
    
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
    response = await llm.ainvoke(messages)
    
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
    response = await llm.ainvoke(messages)
    
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
    response = await llm.ainvoke(messages)
    
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
async def run_scan(domain: str, client_id: str = None, signals: List[str] = None) -> Dict:
    """Entry point for the scanning process.

    signals: optional discovery signals (e.g. ["exposed_api"]) that the Analyst
    and Editor prioritize and reference in the executive summary.
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
    
    # Run the graph
    final_state = await app.ainvoke(initial_state)
    
    # Post-processing: Save to DB (Simulated here)
    if final_state.get("risk_score", 100) < 80:
        print(f"[SUCCESS] High-risk lead identified: {domain} (Score: {final_state['risk_score']})")
    else:
        print(f"[INFO] Low-risk domain: {domain} (Score: {final_state['risk_score']})")
        
    return final_state

if __name__ == "__main__":
    # Test the engine
    asyncio.run(run_scan("example.com"))