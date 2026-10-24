#!/usr/bin/env python3
"""Zero-Trust Sentinel - GO-LIVE verification.

The Autopilot is split across two hosts, so this probes both:

  Body (the API, Replit):
  1. GET  /health          -> publicly reachable (not Replit's 307 shield)
  2. POST /capture         -> the Brain can ingest (200 + scan_id)
  3. GET  /task/{id}       -> the pipeline reaches 'completed'/'hot'
  4. GET  /                -> the cockpit HTML ships the Digital Twin card

  Face (the marketing site, InfinityFree static hosting):
  5. GET  /                -> serves the landing page AND its assessment form
                              is wired to the Body (API_BASE -> replit.app)

Prints GO-LIVE (exit 0) when every limb answers, otherwise HOLD (exit 1) and
names the limb that is dead.

    python3 verify_live.py
    python3 verify_live.py --api https://zero-trust-sentinel--onthecontraryan.replit.app
    python3 verify_live.py --face https://zerodaysentinel.xo.je --timeout 420
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import date

import httpx

UA = "Zero-Trust-Sentinel-Verify/1.0 (GO-LIVE probe)"
TEST_DOMAIN = "example.com"
# Terminal states seen in lead_tasks / scan_tasks (db.py).
DONE = {"completed", "hot"}
DEAD = {"failed", "error", "suppressed"}


def shielded(resp: httpx.Response) -> bool:
    """Replit answers anonymous traffic with 307 -> __replshield -> silent-auth."""
    if resp.status_code not in (301, 302, 303, 307, 308):
        return False
    loc = (resp.headers.get("location") or "").lower()
    return "replit" in loc or "replshield" in loc or "silent-auth" in loc


def check_health(client: httpx.Client, site: str):
    try:
        r = client.get(f"{site}/health")
    except httpx.HTTPError as exc:
        return False, f"unreachable: {type(exc).__name__}: {exc}"
    if shielded(r):
        return False, (f"HTTP {r.status_code} -> Replit auth shield. The Body is "
                       "PRIVATE; set the deployment to public visibility.")
    if r.status_code == 404:
        return False, ("HTTP 404 - nothing serves /health here. The static Face "
                       "cannot answer; point --api at the Replit Body "
                       "(https://zero-trust-sentinel--onthecontraryan.replit.app).")
    if r.status_code != 200:
        return False, f"HTTP {r.status_code} from /health"
    try:
        body = r.json()
    except ValueError:
        return False, (f"/health returned non-JSON (static host?): "
                       f"{r.text[:80]!r} - pass --api <replit-body-url>")
    if body.get("status") != "healthy":
        return False, f"/health says {body.get('status')!r}, expected 'healthy'"
    return True, f"HTTP 200 {body}"


def check_capture(client: httpx.Client, site: str):
    payload = {
        "domain": TEST_DOMAIN,
        "email": "",
        "name": "GO-LIVE probe",
        "signals": ["custom_domain"],
        "harvey_ref": f"hv-golive-{date.today().isoformat()}",
    }
    try:
        r = client.post(f"{site}/capture", json=payload, timeout=45)
    except httpx.HTTPError as exc:
        return False, None, f"unreachable: {type(exc).__name__}: {exc}"
    if shielded(r):
        return False, None, (f"HTTP {r.status_code} -> Replit auth shield; "
                             "the Brain cannot reach /capture.")
    try:
        body = r.json()
    except ValueError:
        return False, None, f"/capture returned non-JSON: HTTP {r.status_code}"
    if r.status_code == 307:
        return False, None, "API unreachable or shielded: HTTP 307"
    if r.status_code >= 500:
        return False, None, f"API unreachable or shielded: HTTP {r.status_code}"
    if r.status_code != 200:
        return False, None, (f"HTTP {r.status_code} status={body.get('status')} "
                             f"message={body.get('message')}")
    scan_id = body.get("scan_id")
    if not scan_id:
        return False, None, f"HTTP 200 but no scan_id: {body}"
    return True, int(scan_id), f"HTTP 200 status={body.get('status')} scan_id={scan_id}"


def check_task(client: httpx.Client, site: str, scan_id: int, timeout: int):
    deadline = time.time() + timeout
    last = "unknown"
    while time.time() < deadline:
        try:
            r = client.get(f"{site}/task/{scan_id}")
        except httpx.HTTPError as exc:
            return False, f"poll failed: {type(exc).__name__}: {exc}"
        if shielded(r):
            return False, f"HTTP {r.status_code} -> Replit auth shield mid-poll"
        if r.status_code == 200:
            try:
                body = r.json()
            except ValueError:
                body = {}
            last = body.get("status") or last
            if last in DONE:
                return True, f"status={last} after poll"
            if last in DEAD:
                return False, f"status={last} - pipeline is dead for this task"
        time.sleep(5)
    return False, f"still {last!r} after {timeout}s - pipeline stalled"


def check_cockpit(client: httpx.Client, api: str):
    """The subscriber cockpit served by the Body at its root."""
    try:
        r = client.get(f"{api}/")
    except httpx.HTTPError as exc:
        return False, f"unreachable: {type(exc).__name__}: {exc}"
    if shielded(r):
        return False, f"HTTP {r.status_code} -> Replit auth shield; the cockpit is private"
    if r.status_code != 200:
        return False, f"HTTP {r.status_code} from /"
    page = r.text
    missing = [needle for needle in ('id="digital-twin"', 'id="twin-locked"',
                                     '">--</div>')
               if needle not in page]
    if missing:
        return False, "cockpit HTML missing " + ", ".join(missing)
    return True, "digital-twin card present, '--' placeholders in place"


def check_face(client: httpx.Client, face: str, api: str):
    """The public marketing Face: live, and its form wired to the Body.

    InfinityFree fronts HTML with a JS anti-bot challenge (/aes.js) that only a
    real browser solves. Scripted clients get the challenge page, so when the
    wall is up we fall back to proving the site's own assets are being served
    (brand CSS is unique to this site) and say exactly what was checked.
    """
    try:
        r = client.get(f"{face}/")
    except httpx.HTTPError as exc:
        return False, f"unreachable: {type(exc).__name__}: {exc}"
    if shielded(r):
        return False, f"HTTP {r.status_code} -> auth shield; the Face is private"
    if r.status_code != 200:
        return False, f"HTTP {r.status_code} from {face}/"
    page = r.text
    host = api.split("//", 1)[-1].rstrip("/")

    if "aes.js" in page and "Run Assessment" not in page:
        # Anti-bot wall is up for this client. Verify via brand assets instead.
        try:
            c = client.get(f"{face}/assets/css/site.css")
        except httpx.HTTPError as exc:
            return False, f"asset probe failed: {type(exc).__name__}: {exc}"
        css = c.text if c.status_code == 200 else ""
        brand = any(m in css for m in ("wordmark", "hero-split", "Zero-Trust"))
        if not brand:
            return False, (f"HTML behind aes.js wall AND brand CSS missing "
                           f"(css HTTP {c.status_code}, {len(css)} bytes)")
        return True, ("200; HTML behind aes.js anti-bot wall (browser-solves it), "
                      "brand CSS served and matches this site")

    if "Run Assessment" not in page:
        return False, "landing page has no assessment form"
    # The form must POST to the Body, not to the static origin itself.
    if host not in page:
        return False, (f"assessment form is not wired to the Body "
                       f"(API_BASE does not mention {host})")
    return True, f"200, assessment form wired to {host}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-Trust Sentinel GO-LIVE probe")
    ap.add_argument("--api", "--site", dest="api",
                    default="https://zero-trust-sentinel--onthecontraryan.replit.app",
                    help="Base URL of the Body/API (default: %(default)s)")
    ap.add_argument("--face",
                    default="https://zerodaysentinel.xo.je",
                    help="Base URL of the public Face (default: %(default)s)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="seconds to wait for the scan to complete")
    args = ap.parse_args()
    api = args.api.rstrip("/")
    face = args.face.rstrip("/")

    results = []
    with httpx.Client(headers={"User-Agent": UA}, follow_redirects=False,
                      timeout=30) as client:
        print(f"Verifying Body={api}\n       Face={face}\n" + "-" * 60)

        ok, detail = check_health(client, api)
        results.append(("Body /health", ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  Body  GET /health          {detail}")

        ok_cap, scan_id, detail = check_capture(client, api)
        results.append(("Brain /capture", ok_cap, detail))
        print(f"  {'PASS' if ok_cap else 'FAIL'}  Brain POST /capture        {detail}")

        if ok_cap and scan_id:
            ok, detail = check_task(client, api, scan_id, args.timeout)
        else:
            ok, detail = False, "skipped - no scan_id to poll"
        results.append(("Pipeline /task", ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  Pipe  GET /task/{scan_id or '?':<8}  {detail}")

        ok, detail = check_cockpit(client, api)
        results.append(("Cockpit / (Digital Twin)", ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  Cock  GET / (Body)         {detail}")

        ok, detail = check_face(client, face, api)
        results.append(("Face / (wired form)", ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  Face  GET / (Face)         {detail}")

    dead = [name for name, ok, _ in results if not ok]
    print("-" * 60)
    if not dead:
        print("GO-LIVE: every limb answered. The Autopilot is live.")
        return 0
    print(f"HOLD: {len(dead)} limb(s) dead -> {', '.join(dead)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
