import base64
import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, List, Optional

def robust_json_parse(content: str) -> Any:
    """
    Robustly parses JSON from LLM output, handling common LLM quirks:
    - Markdown code blocks (```json ... ```)
    - Leading/Trailing text
    - Single quotes instead of double quotes (fallback)
    """
    if not content:
        return {}
        
    # 1. Remove Markdown code blocks
    content = re.sub(r'^```(?:json)?\s*', '', content, flags=re.MULTILINE)
    content = re.sub(r'\s*```$', '', content, flags=re.MULTILINE)
    
    # 2. Try direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
        
    # 3. Find the first { or [ and last } or ]
    start_idx = -1
    end_idx = -1
    for i, char in enumerate(content):
        if char in ('{', '[') and start_idx == -1:
            start_idx = i
        if char in ('}', ']'):
            end_idx = i
            
    if start_idx != -1 and end_idx != -1:
        json_string = content[start_idx:end_idx+1]
        try:
            return json.loads(json_string)
        except json.JSONDecodeError:
            pass
            
    # 4. Fallback: Return empty dict/list based on expected type or empty dict
    return {}

def sanitize_domain(domain: str) -> str:
    """Ensures domain is clean for scanning."""
    domain = domain.lower().strip()
    # Remove protocol if present
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.replace("http://", "").replace("https://", "")
    # Remove trailing slash
    domain = domain.rstrip('/')
    return domain

def is_valid_domain(domain: str) -> bool:
    """Basic domain validation to avoid wasting API calls on garbage."""
    import re
    domain_pattern = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$', re.IGNORECASE)
    return bool(domain_pattern.match(domain))

def _unsubscribe_secret() -> bytes:
    """Server-side secret for unsubscribe links.

    UNSUB_SECRET wins (set it the same wherever the API and the outbound
    engine run). Falling back to a hash of DATABASE_URL keeps links stable
    across restarts without storing another secret in the environment - the
    DSN itself never leaves the server.
    """
    explicit = os.getenv("UNSUB_SECRET")
    if explicit:
        return explicit.encode("utf-8")
    dsn = os.getenv("DATABASE_URL", "sentinel-local-dev")
    return hashlib.sha256(("zts-unsub:" + dsn).encode("utf-8")).digest()


def unsubscribe_token(lead_id: int) -> str:
    """HMAC token binding an unsubscribe link to exactly one lead."""
    msg = str(int(lead_id)).encode("utf-8")
    sig = hmac.new(_unsubscribe_secret(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def verify_unsubscribe_token(lead_id: int, token: Optional[str]) -> bool:
    """Constant-time check of a token from an unsubscribe link."""
    if not token:
        return False
    expected = unsubscribe_token(lead_id)
    return hmac.compare_digest(expected, str(token).strip())


def trim_scan_for_llm(raw_scan: Dict, max_vulns: int = 5, max_hosts: int = 5) -> Dict:
    """
    Reduces the size of the raw scan data to fit within LLM context limits.
    Prioritizes Critical/High severity vulns and live hosts with titles.
    """
    trimmed = raw_scan.copy()
    
    # 1. Trim Vulnerabilities (Keep top 5 by severity)
    vulns = raw_scan.get("vulnerabilities", [])
    if len(vulns) > max_vulns:
        # Sort by severity: Critical > High > Medium > Low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulns.sort(key=lambda x: severity_order.get(x.get("severity", "low").lower(), 4))
        trimmed["vulnerabilities"] = vulns[:max_vulns]
        
    # 2. Trim Live Hosts (Keep top 5)
    hosts = raw_scan.get("live_hosts", [])
    if len(hosts) > max_hosts:
        trimmed["live_hosts"] = hosts[:max_hosts]
        
    # 3. Remove heavy TLS data (Keep only protocols)
    tls = raw_scan.get("tls", {})
    if tls and "certificates" in tls:
        trimmed["tls"] = {
            "protocols": tls.get("protocols", []),
            "error": tls.get("error")
        }
        
    return trimmed