import subprocess
import json
import asyncio
import os
import time
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List
from utils import robust_json_parse, sanitize_domain, is_valid_domain, trim_scan_for_llm

async def run_subprocess(cmd: str, timeout: int = 120) -> str:
    """Robust async subprocess runner with timeout."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout.decode('utf-8')
    except asyncio.TimeoutError:
        process.kill()
        return "ERROR: Command timed out"
    except Exception as e:
        return f"ERROR: {str(e)}"

async def scan_subdomains_ct(domain: str) -> List[str]:
    """Passive fallback: certificate transparency (crt.sh) over HTTPS.

    Runs when subfinder is not installed (serverless/Vercel builds ship no
    Go binaries). CT logs are public data a browser could fetch - the same
    safety class as subfinder's passive sources.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    def _fetch() -> List[str]:
        req = urllib.request.Request(url, headers={"User-Agent": "Zero-Trust-Sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            rows = json.loads(resp.read().decode("utf-8", "replace"))
        names = set()
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and is_valid_domain(name):
                    names.add(name)
        return sorted(names)

    try:
        names = await asyncio.get_running_loop().run_in_executor(None, _fetch)
        print(f"[SCOUT] CT fallback found {len(names)} name(s) for {domain}")
        return names
    except Exception as e:
        print(f"[SCOUT] CT fallback failed: {e}")
        return []


async def scan_subdomains(domain: str) -> List[str]:
    """Agent 1a: Subdomain Enumeration (subfinder, CT fallback when absent)."""
    domain = sanitize_domain(domain)
    print(f"[SCOUT] Enumerating subdomains for {domain}...")
    cmd = f"subfinder -d {domain} -silent -all"
    output = await run_subprocess(cmd)
    subdomains = [] if output.startswith("ERROR") else [
        line.strip() for line in output.splitlines() if line.strip()
    ]
    if not subdomains:
        # Tool missing (exit 127 -> "ERROR") or genuinely zero results:
        # CT logs still give an honest, passive enumeration.
        subdomains = await scan_subdomains_ct(domain)
    return subdomains

def _plain_probe(host: str) -> Dict:
    """One browser-like GET (no auth, no wordlists) - the httpx fallback."""
    import re as _re
    result = {"url": f"https://{host}", "status_code": None, "title": "", "tech": []}
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}/",
                headers={"User-Agent": "Zero-Trust-Sentinel/1.0 (public-surface probe)"},
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read(8192).decode("utf-8", "replace")
                result["url"] = resp.geturl() or result["url"]
                result["status_code"] = resp.status
            m = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.I | _re.S)
            if m:
                result["title"] = m.group(1).strip()[:200]
            return result
        except Exception:
            continue
    return result


async def probe_live_hosts(subdomains: List[str], deadline: float = None) -> List[Dict]:
    """Agent 1b: HTTP Probing (httpx, plain-GET fallback when absent)."""
    if not subdomains:
        return []

    print(f"[SCOUT] Probing {len(subdomains)} hosts...")
    domains_file = "/tmp/domains.txt"
    with open(domains_file, 'w') as f:
        f.write("\n".join(subdomains))

    cmd = f"httpx -l {domains_file} -json -silent"
    output = await run_subprocess(cmd)

    live_hosts = []
    for line in output.splitlines():
        if not line:
            continue
        data = robust_json_parse(line)
        if data.get("url"):
            live_hosts.append({
                "url": data.get("url"),
                "status_code": data.get("status_code"),
                "title": data.get("title"),
                "tech": data.get("tech", [])
            })

    if not live_hosts and subdomains:
        # httpx missing or silent-failed: probe a bounded number of hosts
        # with plain GETs (sequential, one connection each - no hammering).
        # Each host can cost two 12s timeouts, so the wall-clock deadline is
        # what keeps this stage from eating the whole serverless invocation.
        loop = asyncio.get_running_loop()
        probed = 0
        for host in subdomains[:25]:
            if deadline is not None and time.monotonic() > deadline:
                print(f"[SCOUT] probe budget spent after {probed} host(s)")
                break
            res = await loop.run_in_executor(None, _plain_probe, host)
            probed += 1
            if res["status_code"]:
                live_hosts.append(res)
        if live_hosts:
            print(f"[SCOUT] plain-GET fallback found {len(live_hosts)} live host(s)")
    return live_hosts

async def passive_surface_checks(domain: str, live_hosts: List[Dict],
                                 deadline: float = None) -> List[Dict]:
    """Evidence-based, non-intrusive observations used when nuclei is absent.

    These are NOT vulnerability claims: they record what an unauthenticated
    visitor can plainly observe (missing HSTS, directory listing, server
    version disclosure, dead security contact). Each carries its evidence
    URL so the report and the outreach never overstate what was established.
    """
    findings: List[Dict] = []
    for host in live_hosts[:5]:
        if deadline is not None and time.monotonic() > deadline:
            break
        url = host.get("url")
        if not url:
            continue

        def _head(u=url):
            req = urllib.request.Request(u, headers={"User-Agent": "Zero-Trust-Sentinel/1.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.headers, resp.read(4096).decode("utf-8", "replace")

        try:
            headers, body = await asyncio.get_running_loop().run_in_executor(None, _head)
        except Exception:
            continue

        if str(headers.get("Strict-Transport-Security", "")).strip() == "" and u_ssl_is_https(url):
            findings.append({
                "template_id": "passive-missing-hsts",
                "name": "HSTS header not served",
                "severity": "medium",
                "url": url,
                "matched_at": url,
                "description": "The HTTPS response carries no Strict-Transport-Security header, "
                               "so a first request can be downgraded on hostile networks.",
                "confidence": "high",
                "evidence": "response header observation (no header present)",
            })
        if "<title>Index of /" in body or "Directory listing for" in body:
            findings.append({
                "template_id": "passive-dir-listing",
                "name": "Directory listing enabled",
                "severity": "medium",
                "url": url,
                "matched_at": url,
                "description": "The web root lists its files publicly, exposing implementation detail.",
                "confidence": "high",
                "evidence": "public directory index rendered at the URL",
            })
        server = str(headers.get("Server", ""))
        if server and any(ch.isdigit() for ch in server):
            findings.append({
                "template_id": "passive-server-version-disclosure",
                "name": f"Server version disclosed: {server}",
                "severity": "low",
                "url": url,
                "matched_at": url,
                "description": "The Server header advertises a software version to unauthenticated visitors.",
                "confidence": "high",
                "evidence": f"Server: {server}",
            })
    return findings


def u_ssl_is_https(url: str) -> bool:
    return url.lower().startswith("https://")


async def scan_vulnerabilities(live_hosts: List[Dict],
                                deadline: float = None) -> List[Dict]:
    """Agent 1c: Nuclei Vulnerability Scanning (passive fallback when absent)."""
    if not live_hosts:
        return []
        
    print(f"[SCOUT] Running Nuclei on {len(live_hosts)} hosts...")
    urls_file = "/tmp/urls.txt"
    with open(urls_file, 'w') as f:
        f.write("\n".join([h["url"] for h in live_hosts]))
        
    cmd = f"nuclei -l {urls_file} -severity critical,high -json -silent"
    # The scan shares one serverless deadline with everything else: a tool
    # that needs longer than the time actually left would kill the analysis.
    remaining = None if deadline is None else max(5, int(deadline - time.monotonic()))
    output = await run_subprocess(cmd, timeout=min(300, remaining) if remaining else 300)

    vulns = []
    tool_missing = False
    if output.startswith("ERROR"):
        tool_missing = True
    for line in output.splitlines():
        if not line:
            continue
        data = robust_json_parse(line)
        if data.get("template-id"):
            vulns.append({
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "url": data.get("host"),
                "matched_at": data.get("matched-at"),
                "description": data.get("info", {}).get("description")
            })

    if tool_missing:
        domain = (live_hosts[0].get("url") or "").split("://", 1)[-1].split("/", 1)[0]
        vulns = await passive_surface_checks(domain, live_hosts, deadline=deadline)
        print(f"[SCOUT] nuclei unavailable - {len(vulns)} passive observation(s) recorded")
    return vulns

async def check_tls(domain: str) -> Dict:
    """Agent 1d: TLS Configuration Check (stdlib ssl fallback when absent)."""
    domain = sanitize_domain(domain)
    print(f"[SCOUT] Checking TLS for {domain}...")
    # testssl.sh is slow, run with a tighter timeout
    cmd = f"testssl.sh --json-file - {domain}"
    output = await run_subprocess(cmd, timeout=180)

    data = robust_json_parse(output)
    if isinstance(data, dict) and data:
        return {
            "protocols": data.get("protocols", []),
            "certificates": data.get("certificates", []),
            "scores": data.get("scores", [])
        }
    return await check_tls_stdlib(domain)


async def check_tls_stdlib(domain: str) -> Dict:
    """Handshake the real server with Python's ssl and report what is seen.

    Public information only: protocol versions accepted, certificate subject,
    issuer and expiry - exactly what any browser's lock icon shows.
    """
    def _probe() -> Dict:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                days_left = None
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp.replace(tzinfo=timezone.utc) -
                                 datetime.now(timezone.utc)).days
                return {
                    "protocols": [f"TLSv{tls.version().split('TLSv')[-1]}"],
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "certificates": [{
                        "subject": dict(x for x in cert.get("subject", ())[0]) if cert.get("subject") else {},
                        "issuer": dict(x for x in cert.get("issuer", ())[0]) if cert.get("issuer") else {},
                        "not_after": not_after,
                        "days_remaining": days_left,
                        "san": [v for _, v in cert.get("subjectAltName", ())],
                    }],
                    "scores": [],
                    "source": "stdlib-ssl",
                }
    try:
        result = await asyncio.get_running_loop().run_in_executor(None, _probe)
        print(f"[SCOUT] TLS (stdlib): {result['protocols']} "
              f"cert expires in {result['certificates'][0]['days_remaining']}d")
        return result
    except Exception as e:
        return {"error": f"TLS probe failed: {e}"}

async def run_full_scan(domain: str) -> Dict:
    """
    Orchestrates the full scan pipeline with Pre-Flight Checks.
    Returns a structured JSON dict for the Analyst Agent.
    """
    domain = sanitize_domain(domain)

    # 1. Validation Check
    if not is_valid_domain(domain):
        print(f"[SCOUT] Invalid domain format: {domain}")
        return {"domain": domain, "error": "Invalid domain format"}

    # 2. DNS Resolution Check (Fast Fail)
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[SCOUT] DNS resolution failed for {domain}")
        return {"domain": domain, "error": "DNS resolution failed"}

    print(f"[SCOUT] Starting full scan for {domain}")

    # Recon shares the serverless invocation's wall clock with the LLM phase
    # that follows: without this budget a big domain's probing alone can run
    # past the platform's execution limit and the whole analysis is killed
    # before the Analyst ever runs.
    deadline = time.monotonic() + int(os.getenv("SCAN_BUDGET_SECONDS", "100"))

    # 2. Subdomains
    subdomains = await scan_subdomains(domain)

    # 3. Live Hosts
    live_hosts = await probe_live_hosts(subdomains, deadline=deadline)

    # 3. Vulnerabilities
    vulns = await scan_vulnerabilities(live_hosts, deadline=deadline)

    # 4. TLS (only if recon left the time for it)
    tls_info = await check_tls(domain) if time.monotonic() < deadline else {}
    if not tls_info:
        tls_info = {"error": "skipped - scan budget spent during recon"}

    # 5. Structure & Trim for LLM
    raw_scan = {
        "domain": domain,
        "subdomains_count": len(subdomains),
        "live_hosts": live_hosts,
        "vulnerabilities": vulns,
        "tls": tls_info
    }

    # Trim before returning to LangGraph
    final_scan = trim_scan_for_llm(raw_scan)

    print(f"[SCOUT] Scan complete. Found {len(vulns)} vulns.")
    return final_scan