"""Digital Twin trajectory engine.

Sentinel answers "what is broken?" This engine answers the question a CTO
actually lies awake about: "what happens if it is exploited, and what happens
if we fix it?"

It runs a 50-round attack/defense simulation seeded from the client's REAL
scan (findings, severities, live hosts) and returns a modeled breach
trajectory: time to detect, time to contain, impact window, revenue exposure
at a stated assumption, and how all of it moves when specific mitigations are
deployed.

Honesty rules - the same standard the reports are held to:

- INPUTS ARE REAL. Findings, severities and host counts come from the
  client's actual Sentinel scan. This engine never invents a vulnerability.
- OUTPUTS ARE MODELED. Every number here is a projection computed from the
  assumptions that ship inside the payload (`assumptions`), not a
  measurement. The UI labels it as a model for exactly that reason.
- DETERMINISTIC. Trajectories are seeded from domain + score, so the same
  scan always produces the same trajectory - reproducible and auditable,
  which is what makes it usable in a board conversation.
"""

from __future__ import annotations

import hashlib
import random
import statistics
from typing import Any, Dict, List, Optional

DEFAULT_ROUNDS = 50
DEFAULT_ANNUAL_REVENUE = 10_000_000  # disclosed placeholder; UI lets CTOs set their own

# Per-class contribution to "exposure" - how much a finding of each severity
# moves the modeled probability of initial access. Disclosed in the payload.
SEVERITY_WEIGHT = {"critical": 0.15, "high": 0.08, "medium": 0.03, "low": 0.01}

# Mitigation scenarios. Each factor is disclosed in the trajectory payload so
# a skeptical reader can check the arithmetic instead of trusting the number.
MITIGATIONS: Dict[str, Dict[str, Any]] = {
    "patch_critical_high": {
        "label": "Patch critical & high findings",
        "description": "Removes critical/high findings from the exposure model (remediation plan, applied).",
        "drops_findings": ("critical", "high"),
        "breach_mult": 1.0,   # exposure itself shrinks; no extra multiplier
        "detect_mult": 1.0,
        "contain_mult": 0.7,  # fewer open doors = faster to lock down
        "reputation_mult": 0.5,
    },
    "edge_waf": {
        "label": "WAF / edge controls",
        "description": "Commodity exploitation blocked at the edge; modeled as a 40% cut to per-round breach probability.",
        "drops_findings": (),
        "breach_mult": 0.6,
        "detect_mult": 1.0,
        "contain_mult": 0.8,
        "reputation_mult": 0.8,
    },
    "monitoring_247": {
        "label": "24/7 monitoring & response",
        "description": "Continuous outside-in monitoring with alerting: detection collapses from hours to minutes.",
        "drops_findings": (),
        "breach_mult": 1.0,
        "detect_cap_hours": 0.5,  # detection sampled within 3 minutes - 30 minutes
        "contain_mult": 0.6,
        "reputation_mult": 0.7,
    },
}


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings or []:
        sev = str(f.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _exposure(counts: Dict[str, int], risk_score: int,
              drop: tuple = ()) -> float:
    """0-1 modeled exposure: half from real finding mix, half from the score."""
    finding_weight = sum(
        SEVERITY_WEIGHT[sev] * n for sev, n in counts.items() if sev not in drop
    )
    finding_component = min(1.0, finding_weight)
    score_component = max(0.0, (100 - risk_score) / 100.0)
    return min(1.0, 0.5 * finding_component + 0.5 * score_component)


def _pct(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    frac = k - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def _initial_access_vector(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The real finding most likely to be the way in - highest severity first."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranked = sorted(
        (f for f in (findings or []) if f.get("title")),
        key=lambda f: order.get(str(f.get("severity", "low")).lower(), 4),
    )
    if not ranked:
        return None
    top = ranked[0]
    return {
        "title": top.get("title"),
        "severity": top.get("severity"),
        "business_impact": top.get("business_impact", ""),
    }


def _run_rounds(rng: random.Random, *, rounds: int, p_breach: float,
                severity_factor: float, mitigation: Dict[str, Any],
                hourly_revenue: float) -> Dict[str, Any]:
    """One Monte-Carlo pass. Returns per-round outcomes + aggregates."""
    breach_mult = mitigation.get("breach_mult", 1.0)
    detect_mult = mitigation.get("detect_mult", 1.0)
    contain_mult = mitigation.get("contain_mult", 1.0)
    detect_cap = mitigation.get("detect_cap_hours")
    rep_mult = mitigation.get("reputation_mult", 1.0)

    breaches = 0
    detect_hours: List[float] = []
    contain_hours: List[float] = []
    impact_hours: List[float] = []
    losses: List[float] = []

    for _ in range(rounds):
        p = min(0.9, max(0.02, p_breach * breach_mult))
        if rng.random() >= p:
            continue
        breaches += 1

        # Dwell: how long the intrusion lives before anyone notices.
        dwell = rng.uniform(4.0, 96.0) * (0.6 + 0.4 * severity_factor) * detect_mult
        if detect_cap is not None:
            dwell = min(dwell, rng.uniform(0.05, detect_cap))
        detect_hours.append(dwell)

        # Containment: from alert to threat evicted.
        contain = rng.uniform(2.0, 24.0) * (0.7 + 0.3 * severity_factor) * contain_mult
        contain_hours.append(contain)

        # Recovery: service back to normal operations.
        recover = rng.uniform(2.0, 12.0) * contain_mult

        # Impact window: full loss while contained/recovering, partial (25%)
        # capacity loss while the intrusion is still dwelling unseen.
        impact = 0.25 * dwell + contain + recover
        impact_hours.append(impact)
        losses.append(impact * hourly_revenue)

    return {
        "rounds": rounds,
        "breaches": breaches,
        "breach_rate": round(breaches / rounds if rounds else 0.0, 3),
        "time_to_detect_hours_p50": round(_pct(detect_hours, 0.5), 2),
        "time_to_detect_hours_p95": round(_pct(detect_hours, 0.95), 2),
        "time_to_contain_hours_p50": round(_pct(contain_hours, 0.5), 2),
        "impact_hours_p50": round(_pct(impact_hours, 0.5), 2),
        "impact_hours_p95": round(_pct(impact_hours, 0.95), 2),
        "loss_p50": round(_pct(losses, 0.5), 0),
        "loss_p95": round(_pct(losses, 0.95), 0),
        "_rep_mult": rep_mult,
        "_breaches_for_rep": breaches,
    }


def _reputation_drop(counts: Dict[str, int], breach_rate: float,
                     rep_mult: float) -> int:
    """Modeled reputational score drop, severity-weighted (points 0-100)."""
    base = 3 + 2 * counts.get("critical", 0) + 1 * counts.get("high", 0)
    scaled = base * (0.5 + breach_rate) * rep_mult
    return -int(round(min(25, max(0, scaled))))


def _timeline(scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Event markers for the cockpit timeline, hours from initial access."""
    dwell = scenario["time_to_detect_hours_p50"]
    contain = scenario["time_to_contain_hours_p50"]
    recover = max(1.0, scenario["impact_hours_p95"] - dwell - contain)
    return [
        {"t": 0.0, "event": "Initial access", "note": "exploitation of an exposed finding"},
        {"t": round(dwell * 0.6, 2), "event": "Escalation", "note": "reconnaissance, credential and data access"},
        {"t": round(dwell, 2), "event": "Detected", "note": "first signal an operator can see"},
        {"t": round(dwell + contain, 2), "event": "Contained", "note": "intrusion evicted, access revoked"},
        {"t": round(dwell + contain + recover, 2), "event": "Recovered", "note": "normal operations restored"},
    ]


def simulate_trajectory(risk_score: int,
                        findings: Optional[List[Dict[str, Any]]] = None,
                        raw_scan: Optional[Dict[str, Any]] = None,
                        domain: str = "",
                        rounds: int = DEFAULT_ROUNDS,
                        annual_revenue: Optional[int] = None) -> Dict[str, Any]:
    """Run the Digital Twin simulation for one client's real scan.

    Args:
        risk_score: the client's real 0-100 Sentinel score.
        findings: report's risk_assessment list (severity + title + impact).
        raw_scan: optional raw scan (live host count feeds the assumptions).
        domain: client domain, used as the deterministic seed.
        rounds: simulation rounds (default 50).
        annual_revenue: optional; drives the revenue-loss assumption.

    Returns:
        Trajectory payload: baseline scenario, mitigation scenarios, timeline,
        the real access vector, executive summary, and every assumption used.
    """
    findings = findings or []
    raw_scan = raw_scan or {}
    rounds = max(1, min(200, int(rounds or DEFAULT_ROUNDS)))

    annual_revenue = int(annual_revenue or DEFAULT_ANNUAL_REVENUE)
    hourly_revenue = annual_revenue / 8760.0

    counts = _severity_counts(findings)
    live_hosts = len(raw_scan.get("live_hosts") or [])
    vulns = len(raw_scan.get("vulnerabilities") or [])

    # Deterministic seed: same scan -> same trajectory.
    seed = hashlib.sha256(
        f"{domain}:{risk_score}:{rounds}:{annual_revenue}".encode()
    ).hexdigest()
    rng = random.Random(seed)

    severity_factor = min(2.5, 1.0 + 0.15 * (counts["critical"] + counts["high"]))
    exposure = _exposure(counts, risk_score)
    p_breach = min(0.8, max(0.05, 0.05 + 0.70 * exposure))

    def run(mit: Dict[str, Any]) -> Dict[str, Any]:
        drop = mit.get("drops_findings", ())
        p = min(0.8, max(0.05, 0.05 + 0.70 * _exposure(counts, risk_score, drop)))
        # Patching critical+high removes their severity amplification too.
        sf = 1.0 if set(drop) >= {"critical", "high"} else severity_factor
        out = _run_rounds(random.Random(seed), rounds=rounds, p_breach=p,
                          severity_factor=sf, mitigation=mit,
                          hourly_revenue=hourly_revenue)
        rep_mult = out.pop("_rep_mult")
        breaches = out.pop("_breaches_for_rep")
        effective_rate = breaches / rounds if rounds else 0.0
        out["reputation_drop"] = _reputation_drop(counts, effective_rate, rep_mult)
        out["timeline"] = _timeline(out)
        return out

    baseline = run({})
    scenarios: Dict[str, Dict[str, Any]] = {"baseline": baseline}
    for key, mit in MITIGATIONS.items():
        scenarios[key] = run(mit)
    scenarios["full_stack"] = run({
        "label": "All mitigations deployed",
        "description": "Patched findings, edge controls, and 24/7 monitoring together.",
        "drops_findings": ("critical", "high"),
        "breach_mult": 0.6,
        "contain_mult": 0.42,
        "reputation_mult": 0.35,
        "detect_cap_hours": 0.5,
    })

    vector = _initial_access_vector(findings)
    b = baseline
    f = scenarios["full_stack"]

    def _hours(h: float) -> str:
        if h < 1:
            return f"{round(h * 60)} minutes"
        return f"{h:.1f} hours"

    summary = (
        f"{rounds} attack rounds were simulated against {domain or 'this perimeter'}'s "
        f"measured exposure (score {risk_score}/100; {counts['critical']} critical, "
        f"{counts['high']} high findings{f', {live_hosts} live hosts' if live_hosts else ''}). "
        f"In {b['breaches']} of {rounds} rounds an attacker reached initial access"
        + (f", most likely through \"{vector['title']}\"" if vector else "")
        + f". Median time to detect: {_hours(b['time_to_detect_hours_p50'])}. "
        f"Median impact window: {_hours(b['impact_hours_p50'])} "
        f"(worst 5%: {_hours(b['impact_hours_p95'])}). "
        f"Modeled median revenue exposure: ${b['loss_p50']:,.0f} at the stated "
        f"${hourly_revenue:,.0f}/hour assumption. "
        f"With the full mitigation stack deployed, median detection falls to "
        f"{_hours(f['time_to_detect_hours_p50'])} and modeled median exposure falls to "
        f"${f['loss_p50']:,.0f}."
    )

    assumptions = [
        "This is a modeled simulation, not a measurement or a prediction of any specific attack.",
        "Inputs are real: findings, severities and host counts come from this account's latest Sentinel scan.",
        f"Per-round breach probability starts at {p_breach:.0%} and is derived from the finding mix and the {risk_score}/100 score.",
        "Time-to-detect for an unmonitored perimeter is sampled between 4 and 96 hours, scaled by finding severity.",
        "Impact window counts dwelling at 25% capacity loss, plus containment and recovery at full loss.",
        f"Revenue exposure uses an assumed ${annual_revenue:,.0f}/year business (${hourly_revenue:,.0f}/hour) - set your real number; loss scales linearly.",
        f"Mitigation factors: patching removes critical/high findings from the model; edge controls cut per-round breach probability 40%; 24/7 monitoring caps detection at 30 minutes and cuts containment 40%.",
        "Reproducible: the same scan, rounds and revenue assumption always produce the same trajectory.",
    ]

    return {
        "domain": domain,
        "rounds": rounds,
        "risk_score": risk_score,
        "seed": seed[:16],
        "findings_used": counts,
        "access_vector": vector,
        "annual_revenue_assumed": annual_revenue,
        "hourly_revenue_assumed": round(hourly_revenue, 2),
        "scenarios": scenarios,
        "mitigations": [
            {"key": k, "label": v["label"], "description": v["description"]}
            for k, v in MITIGATIONS.items()
        ],
        "executive_summary": summary,
        "assumptions": assumptions,
        "model": "sentinel-digital-twin/1",
    }
