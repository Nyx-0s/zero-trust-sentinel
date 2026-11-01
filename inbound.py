"""Inbound reply handling: parse -> match -> classify -> decide -> record.

api.py stays a thin HTTP shell; everything that touches reply bytes,
correlation, classification and follow-up stopping lives here:

parse_sendgrid_inbound / parse_form_body / parse_multipart
    Raw webhook bytes -> normalized fields. python-multipart is NOT
    installed in this environment, so multipart bodies are split by hand.
parse_headers / extract_message_ids
    The raw header block SendGrid forwards -> In-Reply-To / References
    tokens (the ids a client quotes back when it answers).
match_reply
    Correlation ids -> lead, strongest evidence first:
    X-ZS-Message-Key -> In-Reply-To/References (Message-ID, provider id,
    message key) -> exact mailbox -> prior send to that mailbox ->
    sender domain. Anything else is 'unmatched' - never guessed.
classify_reply
    Ordered keyword rules (UNSUBSCRIBE beats INTERESTED, etc.); an
    optional LLM pass only when the rules say OTHER, the body is long,
    GROQ_API_KEY is set and REPLY_LLM_CLASSIFY=1 (default OFF).
process_inbound
    Idempotent on external_id: replays return the stored outcome and
    re-run no side effects. Side effects run BEFORE the audit insert
    because they are idempotent - an insert-first order could record the
    row, die, and make every later replay skip a required opt-out.
process_sendgrid_events
    Event-webhook bounces/drops/spam -> mailbox suppression.
"""
from __future__ import annotations

import hashlib
import hmac
import html as html_lib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from db import (
    create_handoff,
    get_inbound_by_external_id,
    get_lead_by_domain,
    get_lead_by_email_strongest,
    get_lead_task,
    get_outbound_by_message_id,
    get_outbound_by_message_key,
    get_outbound_by_provider_id,
    get_outbound_recipient_mailbox,
    insert_inbound_message,
    mark_mailbox_replied,
    suppress_mailbox,
)

# The only valid classification values (stored in inbound_messages.classification).
UNSUBSCRIBE = "UNSUBSCRIBE"
BOUNCE = "BOUNCE"
OUT_OF_OFFICE = "OUT_OF_OFFICE"
NOT_INTERESTED = "NOT_INTERESTED"
INTERESTED = "INTERESTED"
QUESTION = "QUESTION"
OTHER = "OTHER"
VALID_CLASSIFICATIONS = (
    UNSUBSCRIBE, BOUNCE, OUT_OF_OFFICE, NOT_INTERESTED,
    INTERESTED, QUESTION, OTHER,
)

# match_method values - 'unmatched' means WE could not correlate, not that
# the sender is hostile; it must never be confused with a classification.
UNMATCHED = "unmatched"


# =============================================================================
# Raw body parsing (SendGrid Inbound Parse -> normalized fields)
# =============================================================================

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


def _boundary_of(content_type: str) -> str:
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type or "", re.I)
    return (m.group(1) or m.group(2) or "") if m else ""


def parse_form_body(raw: bytes) -> Dict[str, str]:
    """application/x-www-form-urlencoded body -> {field: first value}."""
    from urllib.parse import parse_qs
    text = (raw or b"").decode("utf-8", "replace")
    parsed = parse_qs(text, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def parse_multipart(raw: bytes, boundary: str) -> Dict[str, str]:
    """multipart/form-data body -> {field: first value}, no extra deps.

    Hand-rolled because python-multipart is not installed here; only the
    FIRST occurrence of each name is kept (SendGrid's parse payload has one
    value per form field).
    """
    fields: Dict[str, str] = {}
    if not boundary:
        return fields
    delimiter = b"--" + boundary.encode("utf-8", "replace")
    for part in (raw or b"").split(delimiter):
        part = part.strip(b"\r\n")
        if not part or part.startswith(b"--"):
            continue  # closing delimiter / padding
        if b"\r\n\r\n" in part:
            head, content = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            head, content = part.split(b"\n\n", 1)
        else:
            continue
        content = content.rstrip(b"\r\n")
        m = re.search(
            rb'Content-Disposition:[^\r\n]*\bname\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s;]+))',
            head, re.I)
        if not m:
            continue
        name = next(g for g in m.groups() if g is not None).decode("utf-8", "replace")
        if name and name not in fields:
            fields[name] = content.decode("utf-8", "replace")
    return fields


def parse_headers(raw: str) -> Dict[str, str]:
    """Raw RFC822 header block -> dict (first occurrence wins, folded kept)."""
    headers: Dict[str, str] = {}
    current = ""
    for line in (raw or "").splitlines():
        if not line:
            continue
        if line[:1] in (" ", "\t") and current:
            headers[current] = headers[current] + " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if not name:
            continue
        current = name
        if name not in headers:
            headers[name] = value.strip()
    return headers


def extract_email(value: str) -> str:
    """'Ada <ada@x.com>' / 'mailto:ada@x.com' / 'ada@x.com' -> 'ada@x.com'."""
    if not value:
        return ""
    m = re.search(r"<([^<>]+)>", value)
    candidate = m.group(1) if m else value
    candidate = candidate.strip().removeprefix("mailto:").strip()
    found = _EMAIL_RE.search(candidate)
    return found.group(0) if found else ""


def _html_to_text(html: str) -> str:
    """Minimal HTML -> text for replies that carry only an HTML part."""
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html or "",
                  flags=re.I | re.S)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</(p|div|tr|li|h[1-6])>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return html_lib.unescape(text).strip()


def extract_message_ids(headers: Dict[str, str]) -> Dict[str, Any]:
    """In-Reply-To / References / Message-ID -> quoted id tokens.

    `tokens` is the ordered, de-duplicated list of ids a client is quoting
    back from In-Reply-To then References - exactly the ids that can be
    resolved against outbound_messages.
    """
    def _quoted(value: str) -> List[str]:
        if not value:
            return []
        found = re.findall(r"<([^<>]+)>", value)
        if found:
            return [t.strip() for t in found if t.strip()]
        return [t for t in value.split() if t.strip()]

    in_reply = _quoted(_header(headers, "In-Reply-To"))
    references = _quoted(_header(headers, "References"))
    tokens: List[str] = []
    for token in in_reply + references:
        if token not in tokens:
            tokens.append(token)
    return {
        "message_id": (_quoted(_header(headers, "Message-ID")) or [""])[0],
        "in_reply_to": in_reply,
        "references": references,
        "tokens": tokens,
    }


def _header(headers: Dict[str, str], name: str) -> str:
    """Case-insensitive header lookup."""
    if not headers:
        return ""
    if name in headers:
        return str(headers[name] or "")
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value or "")
    return ""


def derive_external_id(parsed: Dict[str, Any]) -> str:
    """Stable id for one inbound message, so replays are stored exactly once.

    SendGrid's parse `token` is unique per delivery; without it the
    Message-ID decides; as a last resort a digest of sender/thread fields.
    """
    token = str(parsed.get("token") or "").strip()
    if token:
        return f"sg-{token}"
    headers = parsed.get("headers") or {}
    message_id = extract_message_ids(headers).get("message_id") or ""
    if message_id:
        digest = hashlib.sha256(message_id.encode("utf-8", "replace")).hexdigest()
        return f"mid-{digest[:40]}"
    seed = "|".join([
        str(parsed.get("from_address") or ""),
        str(parsed.get("recipient") or ""),
        str(parsed.get("subject") or ""),
        _header(headers, "Date"),
    ])
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()
    return f"sha-{digest[:40]}"


def parse_sendgrid_inbound(raw: bytes, content_type: str = "") -> Dict[str, Any]:
    """SendGrid Inbound Parse body (urlencoded or multipart) -> normalized dict.

    Returns keys: external_id, from_address, recipient, subject, body,
    headers (dict), envelope (dict), token, attachments (count).
    """
    content_type = content_type or ""
    if "multipart/form-data" in content_type.lower():
        fields = parse_multipart(raw, _boundary_of(content_type))
    else:
        fields = parse_form_body(raw)

    headers = parse_headers(fields.get("headers") or "")
    envelope: Dict[str, Any] = {}
    if fields.get("envelope"):
        try:
            decoded = json.loads(fields["envelope"])
            if isinstance(decoded, dict):
                envelope = decoded
        except (ValueError, TypeError):
            envelope = {}

    from_address = extract_email(fields.get("from") or fields.get("sender") or "")
    if not from_address:
        # envelope['from'] is authoritative when the From header is a bare name.
        env_from = envelope.get("from") or []
        if isinstance(env_from, str):
            env_from = [env_from]
        from_address = extract_email(env_from[0] if env_from else "")

    # SendGrid Inbound Parse puts the receiving address in `to` (and often
    # `recipient`); fall back to the To header, then the SMTP envelope.
    recipient = (str(fields.get("recipient") or fields.get("to") or "").strip()
                 or extract_email(_header(headers, "To")))
    if not recipient:
        env_to = envelope.get("to") or []
        if isinstance(env_to, str):
            env_to = [env_to]
        recipient = extract_email(env_to[0] if env_to else "")

    body = fields.get("text") or ""
    if not body.strip() and fields.get("html"):
        body = _html_to_text(fields.get("html") or "")

    attachments = sum(1 for key in fields
                      if re.match(r"attachment\d*(_name)?$", key or ""))

    parsed: Dict[str, Any] = {
        "external_id": "",
        "from_address": from_address,
        "recipient": recipient,
        "subject": str(fields.get("subject") or "").strip(),
        "body": body.strip(),
        "headers": headers,
        "envelope": envelope,
        "token": str(fields.get("token") or "").strip(),
        "attachments": attachments,
    }
    parsed["external_id"] = derive_external_id(parsed)
    return parsed


def webhook_secret_ok(provided: Optional[str]) -> bool:
    """Optional shared-secret auth for the inbound webhooks.

    INBOUND_WEBHOOK_SECRET unset = endpoint open (developer default); set =
    constant-time compare against the header or ?secret= value.
    """
    expected = (os.getenv("INBOUND_WEBHOOK_SECRET") or "").strip()
    if not expected:
        return True
    actual = (provided or "").strip()
    return bool(actual) and hmac.compare_digest(expected, actual)


# =============================================================================
# Reply -> lead correlation
# =============================================================================

async def _lookup_message_token(token: str) -> Optional[Tuple[Dict[str, Any], str]]:
    """Resolve one quoted message id against outbound_messages.

    Tries the RFC Message-ID we wrote (with and without angle brackets),
    then the bare provider id (SendGrid delivers Message-ID as
    <sgid@sendgrid.com> where sgid is the X-Message-Id of the 202), then
    our message key itself. Returns (row, resolved_by) or None.
    """
    token = (token or "").strip()
    if not token:
        return None
    bare = token.strip("<>").strip()
    if not bare:
        return None

    row = await get_outbound_by_message_id(f"<{bare}>")
    if row:
        return row, "message_id"
    row = await get_outbound_by_message_id(bare)
    if row:
        return row, "message_id"

    base = bare.split("@", 1)[0]
    if base and base != bare:
        row = await get_outbound_by_provider_id(base)
        if row:
            return row, "provider_id"
    row = await get_outbound_by_message_key(bare)
    if row:
        return row, "message_key"
    if base and base != bare:
        row = await get_outbound_by_message_key(base)
        if row:
            return row, "message_key"
    return None


async def match_reply(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Correlate one inbound message to a lead. Strongest evidence first.

    Returns {"lead": dict|None, "method": str, "confidence": float,
    "evidence": str}. method is one of: message_key, in_reply_to,
    provider_id, from_address, prior_send, domain, unmatched.
    """
    headers = parsed.get("headers") or {}

    # 1. Our own correlation header, written into every outbound payload.
    key = (_header(headers, "X-ZS-Message-Key")
           or str(parsed.get("zs_message_key") or "")).strip()
    if key:
        row = await get_outbound_by_message_key(key)
        if row:
            lead = await get_lead_task(int(row.get("lead_id") or 0))
            if lead:
                return {"lead": lead, "method": "message_key",
                        "confidence": 0.99, "evidence": f"X-ZS-Message-Key {key}"}

    # 2. What the client quoted back: In-Reply-To / References.
    for token in extract_message_ids(headers).get("tokens", []):
        found = await _lookup_message_token(token)
        if found:
            row, resolved_by = found
            method = {"message_id": "in_reply_to", "provider_id": "provider_id",
                      "message_key": "message_key"}.get(resolved_by, "in_reply_to")
            lead = await get_lead_task(int(row.get("lead_id") or 0))
            if lead:
                return {"lead": lead, "method": method, "confidence": 0.97,
                        "evidence": f"quoted id {token} via {resolved_by}"}

    # 3. Exact mailbox: their address on a lead row (strongest address match).
    from_address = str(parsed.get("from_address") or "").strip()
    if from_address:
        lead = await get_lead_by_email_strongest(from_address)
        if lead:
            return {"lead": lead, "method": "from_address", "confidence": 0.9,
                    "evidence": f"exact mailbox {from_address}"}

        # 4. We have mailed this mailbox before even if no lead row survives.
        outbound = await get_outbound_recipient_mailbox(from_address)
        if outbound:
            lead = await get_lead_task(int(outbound.get("lead_id") or 0))
            if lead:
                return {"lead": lead, "method": "prior_send", "confidence": 0.8,
                        "evidence": f"prior send {outbound.get('message_key', '')}"}

        # 5. Domain fallback: a reply from any address at a known lead domain.
        domain = from_address.split("@", 1)[-1].strip().lower()
        if domain and "." in domain:
            lead = await get_lead_by_domain(domain)
            if lead:
                return {"lead": lead, "method": "domain", "confidence": 0.6,
                        "evidence": f"sender domain {domain}"}

    return {"lead": None, "method": UNMATCHED, "confidence": 0.0,
            "evidence": "no correlation id, mailbox or domain match"}


# =============================================================================
# Classification (ordered rules; optional LLM for OTHER only)
# =============================================================================

_UNSUB_RE = re.compile(
    r"\bunsubscrib\w*|\bopt[\s-]?out\b|\bstop\s+(?:e-?mails?|mail|sending|"
    r"contact(?:ing)?)\b|\bremove\s+(?:me|us)\s+from\b|"
    r"\bdo\s+not\s+(?:contact|e-?mail|mail)\b|\bdon'?t\s+(?:contact|e-?mail|mail)\b|"
    r"\btake\s+me\s+off\b|\bno\s+more\s+(?:e-?mails?|mail|messages)\b|"
    r"\bleave\s+me\s+alone\b|\bdon'?t\s+email\s+(?:me|us)\b", re.I)
_BOUNCE_RE = re.compile(
    r"\bdelivery\s+(?:status\s+notification|has\s+failed|failure(?:\s+notice)?)\b|"
    r"\bmessage\s+not\s+delivered\b|\breturned\s+mail\b|"
    r"\baddress\s+(?:not\s+found|rejected)\b|\buser\s+unknown\b|"
    r"\bmailbox\s+(?:unavailable|not\s+found|does'?nt\s+exist)\b|"
    r"\brecipient\s+address\s+rejected\b|\b5\.\d\.\d\b", re.I)
_OOO_RE = re.compile(
    r"\bout\s+of\s+(?:the\s+)?office\b|\bautomatic\s+reply\b|\bautoreply\b|"
    r"\bon\s+vacation\b|\baway\s+from\s+(?:the\s+)?office\b|"
    r"\bcurrently\s+out\b|\baway\s+until\b", re.I)
_NOT_INTERESTED_RE = re.compile(
    r"\bnot\s+interested\b|\bno\s+thanks\b|\bnot\s+(?:a\s+)?(?:priority|a\s+fit|"
    r"right\s+now)\b|\bwe\s+(?:are|'re)\s+(?:happy|satisfied|content)\s+with\b|"
    r"\bnot\s+looking\s+for\b|\bno\s+need\b", re.I)
_INTERESTED_RE = re.compile(
    r"\binterested\b|\bsounds\s+(?:good|great)\b|\btell\s+me\s+more\b|"
    r"\blet'?s\s+(?:talk|discuss|chat|do\s+it)\b|\bcan\s+we\s+(?:schedule|talk|"
    r"discuss|meet)\b|\bsend\s+(?:me\s+)?(?:more|details|info|pricing)\b|"
    r"\bhow\s+much\b|\bpricing\b|\bwhat\s+(?:does\s+it\s+)?cost\b|"
    r"\bbook\s+(?:a|the)\s+(?:demo|call)\b|\bcount\s+me\s+in\b|"
    r"\bi'?d\s+like\s+to\b|\bsign\s+(?:me|us)\s+up\b|\bget\s+started\b", re.I)
_BOUNCE_SENDERS = ("mailer-daemon", "postmaster", "mail-delivery", "ndaemon")


def classify_rules(subject: str, body: str, from_address: str = "") -> Tuple[str, float, str]:
    """Ordered keyword rules. Order is the contract: an opt-out beats a
    'sounds good' quoted inside it, a bounce beats the autoresponder text
    around it, and a question mark is only a QUESTION once nothing above
    matched.
    """
    text = f"{subject or ''}\n{body or ''}"
    sender = (from_address or "").lower()

    if _UNSUB_RE.search(text):
        return UNSUBSCRIBE, 0.95, "rule:opt-out wording"
    if (any(tag in sender for tag in _BOUNCE_SENDERS)
            or _BOUNCE_RE.search(text)):
        return BOUNCE, 0.9, "rule:bounce/delivery-failure"
    if _OOO_RE.search(text):
        return OUT_OF_OFFICE, 0.85, "rule:auto-reply/out-of-office"
    if _NOT_INTERESTED_RE.search(text):
        return NOT_INTERESTED, 0.9, "rule:decline wording"
    if _INTERESTED_RE.search(text):
        return INTERESTED, 0.9, "rule:engagement wording"
    if "?" in (body or ""):
        return QUESTION, 0.65, "rule:contains question mark"
    stripped = (body or "").strip()
    if re.match(r"^(?:what|how|when|where|why|can|could|does|do|is|are|would|will)\b",
                stripped, re.I):
        return QUESTION, 0.6, "rule:interrogative opener"
    return OTHER, 0.3, "rule:no match"


def _llm_enabled() -> bool:
    """LLM classification is opt-in: flag + key must both be present."""
    flag = (os.getenv("REPLY_LLM_CLASSIFY") or "").strip().lower()
    return flag in ("1", "true", "yes") and bool(os.getenv("GROQ_API_KEY"))


async def _llm_classify(subject: str, body: str,
                        from_address: str) -> Optional[Tuple[str, float, str]]:
    """Optional Groq pass for long OTHER replies. Never raises, never logs
    the key; returns None so the rule result stands when anything is off.
    """
    try:
        from main import llm  # lazy: only reached when explicitly enabled
        if llm is None:
            return None
        prompt = (
            "Classify this email reply into exactly one of: "
            f"{', '.join(VALID_CLASSIFICATIONS)}. "
            "Reply with ONLY a JSON object: "
            '{"classification": "...", "confidence": 0.0-1.0, "evidence": "short reason"}\n'
            f"From: {from_address}\nSubject: {subject}\n\nBody:\n{body[:4000]}"
        )
        response = await llm.ainvoke(prompt)
        content = str(getattr(response, "content", "") or response or "")
        match = re.search(r"\{.*\}", content, re.S)
        if not match:
            return None
        data = json.loads(match.group(0))
        classification = str(data.get("classification") or "").strip().upper()
        if classification not in VALID_CLASSIFICATIONS:
            return None
        try:
            confidence = float(data.get("confidence") or 0.6)
        except (TypeError, ValueError):
            confidence = 0.6
        confidence = max(0.0, min(1.0, confidence))
        evidence = str(data.get("evidence") or "llm classification")[:300]
        return classification, confidence, f"llm:{evidence}"
    except Exception as e:  # noqa: BLE001 - degrade to the rule result
        print(f"[INBOUND] LLM classify skipped: {type(e).__name__}")
        return None


async def classify_reply(subject: str, body: str, from_address: str = "",
                         headers: Optional[Dict[str, str]] = None
                         ) -> Tuple[str, float, str]:
    """Classify one reply -> (classification, confidence, evidence).

    The LLM runs ONLY when the rules produced OTHER, the body is long
    enough to carry meaning (>200 chars), GROQ_API_KEY exists and
    REPLY_LLM_CLASSIFY=1 - default is OFF, so classification is fully
    deterministic unless an operator opts in.
    """
    classification, confidence, evidence = classify_rules(
        subject or "", body or "", from_address or "")
    if classification != OTHER:
        return classification, confidence, evidence
    if not _llm_enabled() or len(body or "") <= 200:
        return classification, confidence, evidence
    llm_result = await _llm_classify(subject or "", body or "", from_address or "")
    if llm_result:
        return llm_result
    return classification, confidence, evidence


# =============================================================================
# Decisions and processing
# =============================================================================

def decide_actions(classification: str, matched: bool) -> Dict[str, bool]:
    """Pure decision table: what one classification must do to the mailbox.

    suppress        - opt-out/bounce: bind EVERY lead row for the address
    mark_replied    - a human answered or declined: stop the sequence
    stopped         - follow-ups must not continue for this mailbox
    suppressed      - do-not-contact (stronger than a reply)
    needs_human     - a person should look at this (handoff only if matched)
    """
    classification = classification if classification in VALID_CLASSIFICATIONS else OTHER
    hard_stop = classification in (UNSUBSCRIBE, BOUNCE, NOT_INTERESTED,
                                   INTERESTED, QUESTION)
    return {
        "suppress": classification in (UNSUBSCRIBE, BOUNCE),
        "mark_replied": (classification in (NOT_INTERESTED, INTERESTED, QUESTION)
                         or (classification == OTHER and matched)),
        "stopped": hard_stop or (classification == OTHER and matched),
        "suppressed": classification in (UNSUBSCRIBE, BOUNCE),
        "needs_human": classification in (INTERESTED, QUESTION),
    }


def _extract_bounce_recipient(text: str) -> str:
    """The dead address inside a bounce notice ('Final-Recipient: ...')."""
    if not text:
        return ""
    m = re.search(
        r"(?:Final-Recipient|Original-Recipient|Action|To)\s*:\s*"
        r"(?:rfc822;)?\s*<?([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})>?",
        text, re.I)
    if m:
        return m.group(1)
    return ""


async def process_inbound(parsed: Dict[str, Any],
                          source: str = "sendgrid") -> Dict[str, Any]:
    """Store and act on one inbound message. Idempotent on external_id.

    Order matters: classify and act FIRST (side effects are idempotent),
    insert the audit row AFTER, then open the handoff - so a crash between
    any two steps is repaired by the provider's replay instead of skipped.
    """
    external_id = str(parsed.get("external_id") or "").strip()
    if not external_id:
        parsed = dict(parsed)
        external_id = derive_external_id(parsed)
        parsed["external_id"] = external_id

    existing = await get_inbound_by_external_id(external_id)
    if existing:
        # Replay (or double delivery): report the stored outcome, re-run NOTHING.
        return {
            "received": True,
            "duplicate": True,
            "inbound_id": existing.get("id"),
            "lead_id": existing.get("lead_id"),
            "match_method": existing.get("match_method") or UNMATCHED,
            "classification": existing.get("classification") or OTHER,
            "needs_human": bool(existing.get("needs_human")),
            "suppressed": bool(existing.get("suppressed")),
            "stopped_followups": bool(existing.get("stopped_followups")),
            "handoff_id": None,
        }

    from_address = str(parsed.get("from_address") or "").strip()
    recipient = str(parsed.get("recipient") or "").strip()
    subject = str(parsed.get("subject") or "").strip()
    body = str(parsed.get("body") or "")
    headers = parsed.get("headers") or {}

    match = await match_reply(parsed)
    lead = match.get("lead")
    classification, confidence, evidence = await classify_reply(
        subject, body, from_address, headers)

    actions = decide_actions(classification, matched=lead is not None)

    # A bounce notice arrives FROM the server, but the address that died is
    # inside it - suppress that one, not mailer-daemon.
    suppress_target = from_address
    if actions["suppress"] and classification == BOUNCE:
        dead = (_extract_bounce_recipient(body)
                or _extract_bounce_recipient(json.dumps(headers)))
        if dead:
            suppress_target = dead

    if actions["suppress"]:
        if suppress_target:
            await suppress_mailbox(suppress_target, classification.lower())
    elif actions["mark_replied"] and from_address:
        await mark_mailbox_replied(from_address, classification)

    inbound_id = await insert_inbound_message(
        external_id=external_id, source=source, from_address=from_address,
        recipient=recipient, subject=subject, body=body,
        lead_id=(lead or {}).get("id"),
        match_method=match["method"], classification=classification,
        classification_confidence=confidence, evidence=evidence,
        stopped_followups=actions["stopped"],
        suppressed=actions["suppressed"],
        needs_human=actions["needs_human"],
        raw_headers=headers,
    )

    handoff_id = None
    if actions["needs_human"] and lead:
        detail = "\n".join([
            str(lead.get("domain") or ""),
            subject,
            (body or "")[:600],
        ]).strip()
        handoff_id = await create_handoff(
            inbound_id=inbound_id, lead_id=lead.get("id"),
            classification=classification,
            title=f"{classification} reply from {from_address or 'unknown'}",
            detail=detail,
        )

    print(f"[INBOUND] {classification} | match={match['method']} | "
          f"lead={lead.get('id') if lead else None} | from={from_address}")

    return {
        "received": True,
        "duplicate": False,
        "inbound_id": inbound_id,
        "lead_id": (lead or {}).get("id"),
        "match_method": match["method"],
        "classification": classification,
        "confidence": confidence,
        "needs_human": actions["needs_human"],
        "suppressed": actions["suppressed"],
        "stopped_followups": actions["stopped"],
        "handoff_id": handoff_id,
    }


# Event-webhook states that must stop contact for the address.
_EVENT_STOPS = {"bounce", "dropped", "blocked", "spamreport",
                "unsubscribe", "group_unsubscribe"}


async def process_sendgrid_events(payload: Any) -> Dict[str, Any]:
    """SendGrid Event Webhook -> suppression for terminal events.

    The event webhook is a JSON array (or a single event object). Only
    address-terminating events act; delivered/deferred/open are ignored
    (they carry no compliance obligation and re-writing state for them
    would just be noise).
    """
    if isinstance(payload, list):
        events = [e for e in payload if isinstance(e, dict)]
    elif isinstance(payload, dict):
        if isinstance(payload.get("events"), list):
            events = [e for e in payload["events"] if isinstance(e, dict)]
        elif payload.get("event"):
            events = [payload]
        else:
            events = []
    else:
        events = []

    suppressed = 0
    processed = 0
    for event in events:
        processed += 1
        name = str(event.get("event") or "").strip().lower()
        if name not in _EVENT_STOPS:
            continue
        email = str(event.get("email") or "").strip()
        if not email:
            continue
        reason = str(event.get("reason") or event.get("notification") or name)
        await suppress_mailbox(email, f"event:{name}:{reason}"[:120])
        suppressed += 1

    if suppressed:
        print(f"[INBOUND] events: suppressed {suppressed} mailbox(es) "
              f"of {processed} event(s)")
    return {"received": True, "processed": processed, "suppressed": suppressed}
