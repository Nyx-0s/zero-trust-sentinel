import subprocess
import json
import asyncio
import time
import socket
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

async def scan_subdomains(domain: str) -> List[str]:
    """Agent 1a: Subdomain Enumeration."""
    domain = sanitize_domain(domain)
    print(f"[SCOUT] Enumerating subdomains for {domain}...")
    cmd = f"subfinder -d {domain} -silent -all"
    output = await run_subprocess(cmd)
    if output.startswith("ERROR"):
        return []
    subdomains = [line.strip() for line in output.splitlines() if line.strip()]
    return subdomains

async def probe_live_hosts(subdomains: List[str]) -> List[Dict]:
    """Agent 1b: HTTP Probing."""
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
    return live_hosts

async def scan_vulnerabilities(live_hosts: List[Dict]) -> List[Dict]:
    """Agent 1c: Nuclei Vulnerability Scanning."""
    if not live_hosts:
        return []
        
    print(f"[SCOUT] Running Nuclei on {len(live_hosts)} hosts...")
    urls_file = "/tmp/urls.txt"
    with open(urls_file, 'w') as f:
        f.write("\n".join([h["url"] for h in live_hosts]))
        
    cmd = f"nuclei -l {urls_file} -severity critical,high -json -silent"
    output = await run_subprocess(cmd, timeout=300)
    
    vulns = []
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
    return vulns

async def check_tls(domain: str) -> Dict:
    """Agent 1d: TLS Configuration Check."""
    domain = sanitize_domain(domain)
    print(f"[SCOUT] Checking TLS for {domain}...")
    # testssl.sh is slow, run with a tighter timeout
    cmd = f"testssl.sh --json-file - {domain}"
    output = await run_subprocess(cmd, timeout=180)
    
    data = robust_json_parse(output)
    if isinstance(data, dict):
        return {
            "protocols": data.get("protocols", []),
            "certificates": data.get("certificates", []),
            "scores": data.get("scores", [])
        }
    return {"error": "TLS parse failed"}

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

    # 2. Subdomains
    subdomains = await scan_subdomains(domain)

    # 3. Live Hosts
    live_hosts = await probe_live_hosts(subdomains)

    # 3. Vulnerabilities
    vulns = await scan_vulnerabilities(live_hosts)

    # 4. TLS
    tls_info = await check_tls(domain)

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