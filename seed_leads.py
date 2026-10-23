#!/usr/bin/env python3
"""Zero-Trust Sentinel - Seed Automation.

Reads marketing/seed_leads.csv, requests a public Security Posture Report for
each domain (GET /report/{domain}), waits for each scan to finish, and writes
the top 3 risks per domain to marketing/social_proof.json - ready to quote in
the LinkedIn post (marketing/linkedin_hook.txt).

Usage:
    python3 seed_leads.py                       # against http://localhost:8000
    python3 seed_leads.py --base-url https://api.yourdomain.com
    python3 seed_leads.py --timeout 600

Exit codes: 0 = every seed lead produced a report, 1 = at least one failed.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

import httpx

DEFAULT_BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "marketing", "seed_leads.csv")
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "marketing", "social_proof.json")


def poll_task(client: httpx.Client, base_url: str, task_id: str, timeout: float) -> str:
    """Polls GET /task/{id} until completed/failed. Returns final status."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            task = client.get(f"{base_url}/task/{task_id}").json()
        except httpx.HTTPError as exc:
            print(f"    poll error: {exc}")
            time.sleep(2)
            continue
        status = task.get("status")
        if status in ("hot", "completed"):
            return "completed"
        if status == "failed":
            return "failed"
        time.sleep(2)
    return "timeout"


def seed_one(client: httpx.Client, base_url: str, row: dict, timeout: float) -> dict:
    domain = row["domain"].strip()
    entry = {
        "domain": domain,
        "industry": row.get("industry", ""),
        "hook_risk_score": row.get("estimated_risk_score", ""),
        "report_url": f"{base_url}/report/{domain}",
        "status": "pending",
    }

    print(f"[SEED] {domain} ...")
    try:
        resp = client.get(f"{base_url}/report/{domain}")
        payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        entry["status"] = "request_failed"
        entry["error"] = str(exc)
        print(f"    FAIL request: {exc}")
        return entry

    if payload.get("status") == "scanning":
        status = poll_task(client, base_url, str(payload.get("task_id")), timeout)
        if status != "completed":
            entry["status"] = status
            print(f"    FAIL scan ({status})")
            return entry
        try:
            payload = client.get(f"{base_url}/report/{domain}").json()
        except (httpx.HTTPError, ValueError) as exc:
            entry["status"] = "report_failed"
            entry["error"] = str(exc)
            print(f"    FAIL report fetch: {exc}")
            return entry

    if payload.get("status") != "completed":
        entry["status"] = payload.get("status", "unknown")
        print(f"    FAIL status={entry['status']}")
        return entry

    top_risks = (payload.get("top_risks") or [])[:3]
    entry.update({
        "status": "completed",
        "risk_score": payload.get("risk_score"),
        "top_risks": [
            {
                "title": r.get("title"),
                "severity": r.get("severity"),
                "business_impact": r.get("business_impact"),
            }
            for r in top_risks
        ],
    })
    print(f"    OK score={entry['risk_score']} risks={len(top_risks)}")
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate public reports for seed leads")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--timeout", type=float, default=300, help="Per-domain scan timeout (s)")
    args = parser.parse_args()

    if not os.path.exists(CSV_PATH):
        print(f"FAIL: {CSV_PATH} not found")
        return 1

    with open(CSV_PATH, newline="") as f:
        rows = list(csv.DictReader(f))

    print(f"Seeding {len(rows)} leads from {CSV_PATH} against {args.base_url}")
    results = []
    with httpx.Client(timeout=30) as client:
        for row in rows:
            results.append(seed_one(client, args.base_url.rstrip("/"), row, args.timeout))

    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url.rstrip("/"),
        "completed": sum(1 for r in results if r["status"] == "completed"),
        "total": len(results),
        "leads": results,
    }
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(document, f, indent=2)

    completed = document["completed"]
    print(f"\nWrote {OUTPUT_PATH} ({completed}/{document['total']} reports ready)")
    print("Quote the top findings in marketing/linkedin_hook.txt as social proof.")
    return 0 if completed == document["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
