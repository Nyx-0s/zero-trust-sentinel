"""Prompt templates for Zero-Trust Sentinel LangGraph agents."""

from __future__ import annotations

from typing import Any, Dict, List


# Prompt template for The Analyst (Contextualizer)
ANALYST_PROMPT = """You are a CISO. Analyze this security scan data for {domain}.
Data: {raw_scan_json}

Identify the top 3 business risks. Do not list every bug. Focus on:
1. Data Exposure (PII, Keys, Admin Panels).
2. Brand Reputational Risk (Phishing, Spoofing).
3. Operational Disruption (DDoS, Misconfig).

Return JSON: 
{
  "risks": [
    {
      "id": int,
      "title": str,
      "severity": "Critical|High|Medium|Low",
      "business_impact": str (1 sentence, money-focused),
      "technical_detail": str
    }
  ]
}"""


# Prompt template for The Fixer (Remediation)
FIXER_PROMPT = """You are a Senior Security Engineer. 
Risks: {risk_assessment_json}

Provide a step-by-step remediation plan for each risk. 
- Be specific. Use code snippets for config files (nginx, docker-compose, DNS records).
- Assume the user is a mid-level developer.

Return JSON:
{
  "fixes": [
    {
      "risk_id": int,
      "steps": [str],
      "code_snippet": str (optional)
    }
  ]
}"""


# Prompt template for The Editor (Polish)
EDITOR_PROMPT = """You are a B2B Copywriter. You write for busy executives.
Tone: Confident, authoritative, concise. No hype.

Write a 150-word executive summary for {domain}.
Current Risk Score: {risk_score}/100.
Top Risks: {risk_assessment_json}

Structure:
1. Start with the risk score and a plain-language headline.
2. Mention the top 2 risks and their business impact (1 sentence each).
3. Include 1 prioritized remediation step.
4. End with a call to action: 'Keep your business safe with Zero-Trust Sentinel.'
{referral_cta}
Do NOT use: 'Urgent', 'Free', 'Act Now'.
Do USE: 'Observation', 'Finding', 'Posture'.

Optional: If this is a shareable public report, add: 'Get your own free scan at Zero-Trust Sentinel.'"""


# Prompt template for The Critic (Self-Healing)
CRITIC_PROMPT = """Critique this report. 
Summary: {executive_summary}
Risks: {risk_assessment_json}
Fixes: {remediation_plan_json}

Check for:
1. Hallucinations (Did you invent a vulnerability not in the raw data?)
2. Tone (Is it too technical?)
3. Completeness (Are all critical risks addressed?)

Return JSON:
{
  "errors": [str],
  "suggestions": [str]
}
If no errors, return empty lists."""


# Prompt template for v0.dev landing page
V0_DEV_PROMPT = """Create a SaaS landing page for 'Zero-Trust Sentinel'.
- Aesthetic: Enterprise Minimalist - no 'hacker' green. Slate grays (#0f172a background, #f8fafc text) with Indigo trust-blue CTAs (#4f46e5). Font: Inter (or Roboto), 1.5 line-height.
- Hero: 'Secure Your Digital Perimeter.' Subhead: 'Automated attack surface monitoring for modern B2B companies.'
- CTA: 'Get Your Free Risk Score' (Triggers a modal asking for Domain).
- Pricing: 2 tiers. $49/mo. $490/yr.
- Features: 'Daily Scanning', 'Business Impact Reports', 'Actionable Fixes', '24/7 Monitoring'.
- Copy tone: Consultant - 'Business Continuity', 'Risk Posture', 'Asset Protection'. No hype.
- Report Section: Shareable PDF carousel with at-a-glance score, top 3 findings, and 'Get your own free scan' CTA.
- Layout: centered, max-width 900px, generous padding, clean cards with subtle shadows, responsive and mobile-readable.

SUBSCRIPTION MODAL (Native PayPal Button - 'Live' and 'Trusted'):
- In the Pricing section, the 'Subscribe for $49/mo' button opens a MODAL (never redirects away).
- Capture step wiring: after POST /capture returns, store the account id globally:
    window.CURRENT_CLIENT_ID = response.client_id;
- The modal reminds them WHY they are paying: fetch GET /report/{domain} for the
  domain they scanned and show their 'Risk Score' (e.g. 65/100) and their
  'Top Risks' (first 3 items of top_risks) above the payment button.
- Inside the modal, render the official PayPal Smart Subscribe Button using EXACTLY this code:

  <div id="paypal-button-container"></div>
  <script src="https://www.paypal.com/sdk/js?client-id=BAA6kidDpEqUmq30fZmQu_Sur_SpK-zF1rNiibMkznTWWuP2OiGiIMQJ3sJE2yPO3RJ_TzNrSxGDqBfNZw&vault=true&intent=subscription&currency=USD"></script>
  <script>
    paypal.Buttons({
        style: {
            shape: 'rect',
            color: 'gold',
            layout: 'vertical',
            label: 'paypal'
        },
        createSubscription: (data, actions) => {
            return actions.subscription.create({
                plan_id: 'P-8E455735W3884671YNLNRSVQ'
            });
        },
        onApprove: async (data, actions) => {
            // 1. Get the subscription ID
            const subscriptionID = data.subscriptionID;

            // 2. Send it to our backend to activate the account
            const response = await fetch('/webhook/paypal-activate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    subscription_id: subscriptionID,
                    client_id: window.CURRENT_CLIENT_ID // Set this via a global var from the capture step
                })
            });

            if (response.ok) {
                window.location.href = `/dashboard/${window.CURRENT_CLIENT_ID}`;
            }
        }
    }).render('#paypal-button-container');
  </script>

- The client-id above is PayPal's PUBLIC JS-SDK identifier (safe to expose) and
  the plan_id is the public $49/mo plan - both are meant to ship in the page.
  To test in sandbox, swap both values in the script tag / plan_id.
- On modal close, remove #paypal-button-container's children so the button can
  be re-rendered cleanly on next open."""


def get_analyst_prompt(domain: str, raw_scan_json: str) -> str:
    """Get the analyst prompt filled with domain and raw scan data."""
    return ANALYST_PROMPT.format(domain=domain, raw_scan_json=raw_scan_json)


def get_fixer_prompt(risk_assessment_json: str) -> str:
    """Get the fixer prompt filled with risk assessment data."""
    return FIXER_PROMPT.format(risk_assessment_json=risk_assessment_json)


def get_editor_prompt(domain: str, risk_score: int, risk_assessment_json: str, is_referral: bool = False) -> str:
    """Get the editor prompt filled with domain, risk score, and risks.

    If is_referral is True, the summary includes the 'Refer a colleague'
    CTA (referral loop growth engine).
    """
    referral_cta = (
        "5. If this is for a referred customer, add: 'Refer a colleague and get 1 month free.'"
        if is_referral
        else ""
    )
    return EDITOR_PROMPT.format(
        domain=domain, risk_score=risk_score, risk_assessment_json=risk_assessment_json,
        referral_cta=referral_cta,
    )


def get_critic_prompt(
    executive_summary: str,
    risk_assessment_json: str,
    remediation_plan_json: str,
) -> str:
    """Get the critic prompt filled with report data."""
    return CRITIC_PROMPT.format(
        executive_summary=executive_summary,
        risk_assessment_json=risk_assessment_json,
        remediation_plan_json=remediation_plan_json,
    )