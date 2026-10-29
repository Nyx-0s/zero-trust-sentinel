#!/usr/bin/env python3
"""Hunter - the Groq-powered prospecting loop (Harvey's job, no Claude CLI).

Harvey (ethanplusai/harvey) needs the Claude or Codex CLI as its brain and has
no Groq mode. Hunter does the same JOB with your Groq key instead:

  1. Reads targets from marketing/seed_leads.csv (domain, industry, score).
  2. Confirms signals per the playbook in harvey_discovery.md - PUBLIC data
     only: DNS lookups and plain GETs a browser could send. No brute force,
     no wordlists, no login attempts.
  3. Asks Groq whether the lead fits the ICP (B2B SaaS / Fintech / E-commerce).
  4. Submits confirmed leads (>=2 signals, custom_domain alone never counts)
     to the Sentinel API's /capture endpoint with signals + harvey_ref.

Run it on your laptop against the deployed API:

    python hunter.py --api https://YOUR-API-HOST --limit 10
    python hunter.py --dry-run          # probe + qualify, submit nothing

Needs GROQ_API_KEY (from env or .env) and outbound internet access.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

# The Face (static InfinityFree hosting) cannot accept POST /capture - leads
# must be ingested by the Body, which owns the API and the database.
# SITE_URL is whatever the deployment actually serves; the old Replit body is
# gone, so a fresh clone must never post leads at a dead host.
API_URL = os.getenv("SITE_URL") or "https://zerodaysentinel.xo.je"
UA = "Zero-Trust-Sentinel-Hunter/1.0 (public-surface discovery; GET-only)"
API_PATHS = ["/docs", "/api", "/swagger", "/swagger-ui/", "/openapi.json", "/api/docs"]
STAGING_PREFIXES = ["staging", "dev", "test", "uat"]
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# Public contact routes we will accept as a lead's email, in order of trust.
# Only addresses literally printed on the prospect's own pages qualify -
# never guessed patterns (info@, sales@ are inventions, not discoveries).
CONTACT_PATHS = ["/", "/contact", "/contact-us", "/about", "/support"]


def load_dotenv(path: str = ".env") -> None:
    """Tiny KEY=VALUE reader - no extra dependency."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))


# --- Signal probes (harvey_discovery.md signal dictionary) -------------------

def resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 443)
        return True
    except (socket.gaierror, OSError):
        return False


def probe(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    try:
        return client.get(url, timeout=10)
    except httpx.HTTPError:
        return None


def detect_signals(client: httpx.Client, domain: str) -> Tuple[List[str], Dict[str, Any]]:
    """Confirm signals with public, browser-level GETs and DNS lookups."""
    signals: List[str] = []
    evidence: Dict[str, Any] = {}

    # custom_domain: the apex answers over HTTPS at all (identity, never enough alone)
    home = probe(client, f"https://{domain}/")
    if home is not None:
        signals.append("custom_domain")
        evidence["homepage_status"] = home.status_code
        evidence["homepage_text"] = home.text[:3000]

    # exposed_api: a live /docs, /api, /swagger or /openapi endpoint
    for path in API_PATHS:
        r = probe(client, f"https://{domain}{path}")
        if r is not None and r.status_code == 200 and len(r.content) > 0:
            ctype = (r.headers.get("content-type") or "").lower()
            if "html" in ctype or "json" in ctype:
                signals.append("exposed_api")
                evidence["exposed_api_url"] = f"https://{domain}{path}"
                break
        time.sleep(0.3)

    # staging_exposed: staging./dev./test./uat. resolve publicly
    for prefix in STAGING_PREFIXES:
        host = f"{prefix}.{domain}"
        if resolves(host):
            sr = probe(client, f"https://{host}/")
            signals.append("staging_exposed")
            evidence["staging_host"] = host
            evidence["staging_status"] = sr.status_code if sr is not None else "dns-only"
            break

    # outdated_security: /security or /trust last touched over 12 months ago
    for path in ("/security", "/trust", "/security.html"):
        r = probe(client, f"https://{domain}{path}")
        if r is not None and r.status_code == 200:
            last_mod = r.headers.get("last-modified")
            if last_mod:
                try:
                    from email.utils import parsedate_to_datetime
                    when = parsedate_to_datetime(last_mod)
                    if (date.today() - when.date()).days > 365:
                        signals.append("outdated_security")
                        evidence["security_page"] = f"https://{domain}{path}"
                        evidence["last_modified"] = last_mod
                        break
                except (TypeError, ValueError):
                    pass
            time.sleep(0.3)

    # running_ads is NOT checked: verifying active ads cheaply and passively is
    # not possible from here, and an unconfirmed signal is never submitted.
    return signals, evidence


def find_contact_email(client: httpx.Client, domain: str,
                        homepage_html: str = "") -> Tuple[str, str]:
    """Find a publicly published business contact for the domain.

    Walks the prospect's own pages (/, /contact, /about) and returns the first
    mailbox that is literally printed there, plus the URL that printed it.
    Never guesses addresses: if the site publishes none, returns ("", "").
    A lead with no published contact is still scanned and reported - it just
    is never mailed.
    """
    seen_pages = {"/": homepage_html} if homepage_html else {}
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@" + re.escape(domain) + r"\b")
    mailto_re = re.compile(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
                           re.I)

    def _pick(page_url: str, html: str) -> Optional[Tuple[str, str]]:
        m = mailto_re.search(html)
        if m:
            return m.group(1).lower(), page_url
        m = email_re.search(html)
        if m:
            addr = m.group(0).lower()
            # Role boxes only - never a personal-looking address scraped from
            # a page (keeps outreach on published, role-based routes).
            local = addr.split("@", 1)[0]
            if local in ("info", "contact", "hello", "security", "support",
                         "team", "admin", "sales", "partners", "press"):
                return addr, page_url
        return None

    for path, html in list(seen_pages.items()):
        hit = _pick(f"https://{domain}{path}", html)
        if hit:
            return hit

    for path in CONTACT_PATHS:
        if path in seen_pages:
            continue
        try:
            r = client.get(f"https://{domain}{path}", timeout=10)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and "html" in (r.headers.get("content-type") or "").lower():
            hit = _pick(str(r.url), r.text)
            if hit:
                return hit
        time.sleep(0.3)
    return "", ""


# --- Groq ICP qualification --------------------------------------------------

def groq_qualify(client: httpx.Client, api_key: str, industry: str,
                 homepage_text: str, signals: List[str]) -> Dict[str, Any]:
    """Ask Groq whether this lead fits the Sentinel ICP. Returns {icp_fit, reason}."""
    prompt = (
        "You qualify leads for an external attack-surface monitoring service for "
        "B2B SaaS, Fintech, and E-commerce companies (roughly 10-50 employees, "
        "with real customers and real uptime pressure).\n"
        f"Target industry from our list: {industry}\n"
        f"Confirmed public signals: {', '.join(signals)}\n"
        f"Homepage excerpt:\n{homepage_text[:1500]}\n"
        'Answer JSON ONLY: {"icp_fit": true|false, "reason": "one sentence"}'
    )
    try:
        last_err = ""
        model = GROQ_MODEL
        fallback = os.getenv("GROQ_MODEL_FALLBACK", "openai/gpt-oss-20b")
        # Groq rate-limits (429) and blips are routine while the pipeline is
        # scanning in parallel: three short attempts before giving up, so one
        # busy minute does not silently mislabel a good prospect as no-fit.
        for attempt, delay in enumerate((0.0, 2.0, 6.0), start=1):
            if delay:
                time.sleep(delay)
            try:
                r = client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={"model": model, "temperature": 0,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=45,
                )
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}"
                    if r.status_code == 429 and model != fallback:
                        # Groq meters tokens PER MODEL per day: the primary's
                        # cap is a wait, but the sibling's budget is still
                        # full - qualification should move there at once.
                        model = fallback
                        last_err = "HTTP 429 - switched to fallback model"
                    continue
                r.raise_for_status()
                content = r.json()["choices"][0]["message"]["content"]
                m = re.search(r"\{.*\}", content, re.DOTALL)
                parsed = json.loads(m.group(0)) if m else {}
                return {"icp_fit": bool(parsed.get("icp_fit")),
                        "reason": str(parsed.get("reason", ""))[:200]}
            except Exception as exc:  # transport/JSON - retry then report
                last_err = f"{type(exc).__name__}: {exc}"[:160]
        # Not an ICP decision: the caller must be able to tell "rejected by
        # the gate" apart from "the gate could not run" (rerun later).
        return {"icp_fit": False,
                "reason": f"qualification unavailable after retries ({last_err}) - "
                          f"re-run to reconsider"}
    except Exception as exc:  # a failed LLM call must never silently submit
        return {"icp_fit": False, "reason": f"qualification failed: {type(exc).__name__}"}


# --- Submission (harvey_discovery.md field contract) -------------------------

def submit(api_base: str, domain: str, signals: List[str],
           harvey_ref: str, email: str = "",
           evidence: Optional[Dict[str, Any]] = None,
           defer: bool = False) -> Tuple[bool, str]:
    """POST /capture with an honest contract.

    Only HTTP 200 *with* a scan_id is an ingest. A 3xx, a 5xx or a transport
    error all mean the lead is NOT confirmed in the Autopilot - they are
    reported as failures, never as submissions. A read timeout after the
    300s window is called out separately: on INLINE_SCAN the Body keeps
    scanning after the client gives up, so the lead usually lands anyway and
    the recovery sweep owns it from there.

    defer=True is the cron path: the Body records the lead and returns at
    once, leaving the analysis to the recovery sweep, so a bounded serverless
    tick can ingest several leads without holding one HTTP call open.
    Returns (ok, detail).
    """
    url = f"{api_base.rstrip('/')}/capture"
    payload: Dict[str, Any] = {
        "domain": domain, "email": email, "name": "Discovered by Hunter",
        "signals": signals, "harvey_ref": harvey_ref,
    }
    if evidence:
        payload["evidence"] = evidence
    if defer:
        payload["defer"] = True
    try:
        r = httpx.post(
            url,
            json=payload,
            # Inline scans run inside this call (Vercel has no detached
            # tasks): recon + LLM analysis can take a couple of minutes.
            # A deferred capture answers immediately, so it need not wait.
            timeout=30 if defer else 300,
        )
    except httpx.ReadTimeout:
        # INLINE_SCAN keeps working after the client gives up: the lead is
        # almost always in the DB already, still scanning.
        return False, ("capture read-timed out at 300s while the Body was "
                       "still scanning - the lead usually lands anyway "
                       "(recovery sweep owns it from here)")
    except httpx.HTTPError as exc:
        return False, f"API unreachable or shielded: {type(exc).__name__}: {exc}"

    ctype = (r.headers.get("content-type") or "").lower()
    body = r.json() if "json" in ctype else {}

    if 300 <= r.status_code < 400:
        return False, (f"API unreachable or shielded: HTTP {r.status_code} -> "
                       f"{r.headers.get('location', '')}")
    if r.status_code >= 500:
        return False, f"API unreachable or shielded: HTTP {r.status_code}"
    if r.status_code != 200:
        msg = body.get("message") or body.get("error") or body.get("status")
        return False, (f"HTTP {r.status_code} status={body.get('status')} "
                       f"message={msg}")
    if not body.get("scan_id"):
        return False, f"HTTP 200 but no scan_id (lead not ingested): {body}"
    return True, (f"HTTP 200 status={body.get('status')} "
                  f"scan_id={body.get('scan_id')}")


def run_hunt(api: str, csv_path: str = "marketing/seed_leads.csv",
             limit: int = 10, dry_run: bool = False, min_signals: int = 2,
             defer: bool = False) -> Dict[str, Any]:
    """One discovery pass: probe -> qualify -> ingest. Returns its counts.

    Shared by the CLI (main) and by the Body's /internal/discover cron tick,
    which needs the same loop as a callable instead of a subprocess.
    """
    load_dotenv()
    groq_key = os.getenv("GROQ_API_KEY", "")
    if not groq_key:
        print("ERR: GROQ_API_KEY not set (env or .env)")
        return {"targets": 0, "qualified": 0, "submitted": 0, "failed": 0,
                "error": "GROQ_API_KEY not set"}

    with open(csv_path, newline="") as fh:
        targets = [r for r in csv.DictReader(fh) if r.get("domain")][:limit]
    print(f"Hunting {len(targets)} targets from {csv_path} against {api}"
          + (" (DRY RUN)" if dry_run else "")
          + (" (deferred scans)" if defer else ""))

    submitted = qualified = failed = 0
    ref_seq = 0
    with httpx.Client(headers={"User-Agent": UA}, follow_redirects=True) as client:
        for t in targets:
            domain = t["domain"].strip().lower()
            industry = (t.get("industry") or "").strip()
            signals, evidence = detect_signals(client, domain)

            # The gate: >=2 signals, and custom_domain alone never counts.
            real = [s for s in signals if s != "custom_domain"]
            if len(real) < min_signals - (1 if "custom_domain" in signals else 0):
                print(f"  {domain:<16} watch-list  signals={signals or 'none'}")
                time.sleep(1.5)
                continue

            fit = groq_qualify(client, groq_key, industry,
                               evidence.get("homepage_text", ""), signals)
            if not fit["icp_fit"]:
                print(f"  {domain:<16} no-fit      signals={signals} why={fit['reason']}")
                time.sleep(1.5)
                continue

            qualified += 1
            ref_seq += 1
            harvey_ref = f"hv-{date.today().isoformat()}-{ref_seq:03d}"
            proof = evidence.get("exposed_api_url") or evidence.get("staging_host") or "-"
            contact, contact_source = find_contact_email(
                client, domain, evidence.get("homepage_text", ""))
            if contact_source:
                evidence["contact_source"] = contact_source
            print(f"  {domain:<16} QUALIFIED   signals={signals} proof={proof}")
            print(f"      contact: {contact or '(none published - scan only, never mailed)'}"
                  + (f" via {contact_source}" if contact_source else ""))
            if dry_run:
                print(f"      (dry run) would POST {api}/capture "
                      f"domain={domain} signals={signals} ref={harvey_ref}")
            else:
                try:
                    ok, detail = submit(api, domain, signals, harvey_ref,
                                        email=contact, evidence=evidence,
                                        defer=defer)
                except Exception as exc:  # a submit must never crash the hunt
                    ok, detail = (False,
                                  f"API unreachable or shielded: "
                                  f"{type(exc).__name__}: {exc}")
                if ok:
                    submitted += 1
                    print(f"      \u2705 [HUNT] {domain} ingested. {detail} "
                          f"ref={harvey_ref}")
                else:
                    failed += 1
                    print(f"      \u274c [HUNT] {domain} failed: {detail}")
            time.sleep(1.5)

    print(f"\nDone: {qualified} qualified, {submitted} ingested"
          + (f", {failed} FAILED" if failed else "")
          + (" (dry run - nothing submitted)" if dry_run else ""))
    return {"targets": len(targets), "qualified": qualified,
            "submitted": submitted, "failed": failed}


def main() -> int:
    ap = argparse.ArgumentParser(description="Groq-powered prospecting loop")
    ap.add_argument("--api", default=os.getenv("HUNTER_API_URL", API_URL),
                    help="Sentinel API base URL (default: %(default)s)")
    ap.add_argument("--csv", default="marketing/seed_leads.csv")
    ap.add_argument("--limit", type=int, default=10, help="max targets to hunt")
    ap.add_argument("--dry-run", action="store_true", help="probe + qualify, submit nothing")
    ap.add_argument("--min-signals", type=int, default=2)
    ap.add_argument("--defer", action="store_true",
                    help="ingest leads without running their analysis inline "
                         "(the cron path: the recovery sweep claims the scans)")
    args = ap.parse_args()

    result = run_hunt(api=args.api, csv_path=args.csv, limit=args.limit,
                      dry_run=args.dry_run, min_signals=args.min_signals,
                      defer=args.defer)
    if result.get("error"):
        return 1
    if not args.dry_run and result.get("failed"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
