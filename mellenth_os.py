"""Mellenth mobile-first sales operations API.

Discovery and marketing permission are separate: a public contact address is
a prospect, not consent to receive campaigns.
"""
from __future__ import annotations

import hmac
import json
import os
from datetime import date
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from db import get_pool

router = APIRouter()
STAGES = {"new", "researching", "qualified", "contacted", "replied",
          "meeting", "proposal", "negotiation", "won", "lost", "suppressed"}
PRODUCTS = [
    {"name": "Zero-Trust Sentinel", "pillar": "Security",
     "offer": "External attack-surface assessment, evidence-backed risk reporting and remediation.",
     "repo": "https://github.com/Nyx-0s/zero-trust-sentinel",
     "maturity": "Operational codebase; live deployment must pass health checks."},
    {"name": "ConsentArk", "pillar": "Automation",
     "offer": "Permission-bounded AI employees with audit trails and human approval gates.",
     "repo": "https://github.com/Nyx-0s/QA-AI-Employee/tree/main/consentark",
     "maturity": "Self-hosted product code; deployment and customer onboarding required."},
    {"name": "Prometheus", "pillar": "Intelligence",
     "offer": "Strategic intelligence and signal-led decision experience.",
     "repo": "https://github.com/Nyx-0s/Prometheus",
     "maturity": "Current repository is a Next.js experience, not a deployed intelligence backend."},
    {"name": "AQW", "pillar": "Automation",
     "offer": "Autonomous QA workforce for repeatable quality operations.",
     "repo": "https://github.com/Nyx-0s/rft-aqw",
     "maturity": "Repository currently empty; do not sell as production-ready."},
    {"name": "AQW Community Edition", "pillar": "Automation",
     "offer": "Community QA automation foundation.",
     "repo": "https://github.com/Nyx-0s/rft-aqw-community-edition",
     "maturity": "Scaffold only; no test script is implemented."},
    {"name": "ADSC / ADSE", "pillar": "Automation",
     "offer": "Institutional data preparation, validation and ERP import automation.",
     "repo": "https://github.com/Nyx-0s/gyansetu-adse",
     "maturity": "Working local Playwright workflow; requires customer-specific setup."},
    {"name": "Arkhe Media Engine", "pillar": "Automation",
     "offer": "Creative and media production workflow automation.",
     "repo": "https://github.com/Nyx-0s/arkhe-media-engine",
     "maturity": "Current repository is a Next.js starter scaffold."},
    {"name": "Research Setu", "pillar": "Intelligence",
     "offer": "Research workflow and literature intelligence platform.",
     "repo": "https://github.com/Nyx-0s/Research-Setu",
     "maturity": "Separate product repository; integration and deployment review required."},
    {"name": "CyberGuard", "pillar": "Security",
     "offer": "Hands-on cybersecurity labs and talent assessment infrastructure.",
     "repo": "https://github.com/Nyx-0s/cyberguard",
     "maturity": "Separate product repository; deployment review required."},
    {"name": "CyberGuard Library", "pillar": "Security",
     "offer": "Reusable cybersecurity lab templates.",
     "repo": "https://github.com/Nyx-0s/CyberGuard-Library",
     "maturity": "Library repository; not a hosted customer service."},
]

def _expected_token() -> str:
    return os.getenv("MELLENTH_ADMIN_TOKEN", "").strip()

def _check_token(token: str) -> None:
    expected = _expected_token()
    if not expected:
        raise HTTPException(status_code=503, detail="MELLENTH_ADMIN_TOKEN is not configured")
    if not token or not hmac.compare_digest(expected, token.strip()):
        raise HTTPException(status_code=401, detail="invalid operator token")

async def operator_auth(x_admin_token: str = Header(default="")) -> None:
    _check_token(x_admin_token)

class LoginBody(BaseModel):
    token: str = Field(min_length=16, max_length=512)

class ProspectCreate(BaseModel):
    company: str = Field(min_length=1, max_length=180)
    domain: str = Field(default="", max_length=255)
    email: str = Field(default="", max_length=255)
    source: str = Field(default="manual", max_length=80)
    segment: str = Field(default="", max_length=100)
    score: int = Field(default=0, ge=0, le=100)
    notes: str = Field(default="", max_length=8000)
    evidence: dict[str, Any] = Field(default_factory=dict)

class ProspectPatch(BaseModel):
    stage: Optional[str] = None
    notes: Optional[str] = Field(default=None, max_length=8000)
    marketing_consent: Optional[bool] = None
    consent_source: Optional[str] = Field(default=None, max_length=500)

class ReplyCreate(BaseModel):
    prospect_id: Optional[int] = None
    email: str = Field(min_length=3, max_length=255)
    domain: str = Field(default="", max_length=255)
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1, max_length=20000)
    channel: str = Field(default="email", max_length=40)

class DealCreate(BaseModel):
    prospect_id: int
    offer: str = Field(min_length=1, max_length=180)
    value_amount: float = Field(ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    stage: str = Field(default="discovery", max_length=40)
    expected_close: Optional[str] = None
    payment_url: str = Field(default="", max_length=1000)
    notes: str = Field(default="", max_length=4000)

class DealPatch(BaseModel):
    stage: Optional[str] = None
    value_amount: Optional[float] = Field(default=None, ge=0)
    expected_close: Optional[str] = None
    payment_url: Optional[str] = Field(default=None, max_length=1000)
    notes: Optional[str] = Field(default=None, max_length=4000)

async def ensure_schema() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
        ALTER TABLE lead_tasks ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE lead_tasks ADD COLUMN IF NOT EXISTS consent_source TEXT;
        ALTER TABLE lead_tasks ADD COLUMN IF NOT EXISTS consent_at TIMESTAMP;
        """)
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS os_prospects (
          id BIGSERIAL PRIMARY KEY,
          lead_task_id INTEGER UNIQUE,
          company TEXT NOT NULL,
          domain VARCHAR(255),
          email VARCHAR(255),
          source VARCHAR(80) NOT NULL DEFAULT 'manual',
          segment VARCHAR(100) NOT NULL DEFAULT '',
          score INTEGER NOT NULL DEFAULT 0,
          stage VARCHAR(32) NOT NULL DEFAULT 'new',
          evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
          notes TEXT NOT NULL DEFAULT '',
          marketing_consent BOOLEAN NOT NULL DEFAULT FALSE,
          consent_source TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS os_prospects_stage_idx ON os_prospects(stage, updated_at DESC);
        CREATE INDEX IF NOT EXISTS os_prospects_email_idx ON os_prospects(lower(email));
        CREATE TABLE IF NOT EXISTS os_replies (
          id BIGSERIAL PRIMARY KEY,
          prospect_id BIGINT REFERENCES os_prospects(id) ON DELETE SET NULL,
          sender_email VARCHAR(255) NOT NULL,
          subject TEXT NOT NULL DEFAULT '',
          body TEXT NOT NULL,
          channel VARCHAR(40) NOT NULL DEFAULT 'email',
          category VARCHAR(40) NOT NULL,
          confidence NUMERIC(4,3) NOT NULL DEFAULT 0.5,
          summary TEXT NOT NULL DEFAULT '',
          next_action TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS os_replies_created_idx ON os_replies(created_at DESC);
        CREATE TABLE IF NOT EXISTS os_activities (
          id BIGSERIAL PRIMARY KEY,
          prospect_id BIGINT REFERENCES os_prospects(id) ON DELETE CASCADE,
          kind VARCHAR(40) NOT NULL,
          detail TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS os_activities_created_idx ON os_activities(created_at DESC);
        CREATE TABLE IF NOT EXISTS os_deals (
          id BIGSERIAL PRIMARY KEY,
          prospect_id BIGINT NOT NULL REFERENCES os_prospects(id) ON DELETE CASCADE,
          offer TEXT NOT NULL,
          value_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
          currency CHAR(3) NOT NULL DEFAULT 'USD',
          stage VARCHAR(40) NOT NULL DEFAULT 'discovery',
          expected_close DATE,
          payment_url TEXT NOT NULL DEFAULT '',
          notes TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS os_deals_stage_idx ON os_deals(stage, updated_at DESC);
        """)
        await conn.execute("""
        INSERT INTO os_prospects
          (lead_task_id, company, domain, email, source, score, evidence, stage, marketing_consent, consent_source)
        SELECT t.id, COALESCE(NULLIF(t.name,''), t.domain, 'Unknown'),
               t.domain, NULLIF(t.email,''), 'sentinel-hunter',
               COALESCE((SELECT r.risk_score FROM reports r
                 JOIN clients c ON c.id = r.client_id
                 WHERE c.domain = t.domain ORDER BY r.created_at DESC LIMIT 1), 0),
               COALESCE(t.metadata, '{}'::jsonb),
               CASE WHEN t.status = 'suppressed' THEN 'suppressed'
                    WHEN t.status = 'hot' THEN 'qualified' ELSE 'new' END,
               t.marketing_consent, t.consent_source
        FROM lead_tasks t
        ON CONFLICT (lead_task_id) DO UPDATE SET
          email = COALESCE(NULLIF(EXCLUDED.email,''), os_prospects.email),
          evidence = EXCLUDED.evidence,
          marketing_consent = EXCLUDED.marketing_consent,
          consent_source = EXCLUDED.consent_source,
          score = GREATEST(os_prospects.score, EXCLUDED.score),
          updated_at = NOW()
        """)

@router.get("/mellenth")
async def mellenth_dashboard():
    return FileResponse(Path(__file__).parent / "static" / "mellenth.html")

@router.post("/api/os/login")
async def operator_login(body: LoginBody):
    _check_token(body.token)
    return {"ok": True}

@router.get("/api/os/health", dependencies=[Depends(operator_auth)])
async def os_health():
    return {"ok": True, "service": "mellenth-operations",
            "admin_token_configured": bool(_expected_token()),
            "email_sender_configured": bool(os.getenv("SENDGRID_API_KEY") or os.getenv("RESEND_API_KEY")),
            "llm_configured": bool(os.getenv("GROQ_API_KEY")),
            "reply_ingestion": "manual-mobile-inbox until inbound mailbox webhook is configured"}

@router.get("/api/os/products", dependencies=[Depends(operator_auth)])
async def products():
    return PRODUCTS

async def _sync_prospects(conn) -> None:
    await conn.execute("""
      INSERT INTO os_prospects (lead_task_id, company, domain, email, source, evidence, stage, marketing_consent, consent_source)
      SELECT t.id, COALESCE(NULLIF(t.name,''), t.domain, 'Unknown'), t.domain,
             NULLIF(t.email,''), 'sentinel-hunter', COALESCE(t.metadata,'{}'::jsonb),
             CASE WHEN t.status='suppressed' THEN 'suppressed'
                  WHEN t.status='hot' THEN 'qualified' ELSE 'new' END,
             t.marketing_consent, t.consent_source
      FROM lead_tasks t
      ON CONFLICT (lead_task_id) DO UPDATE SET
        email=COALESCE(NULLIF(EXCLUDED.email,''),os_prospects.email),
        evidence=EXCLUDED.evidence, marketing_consent=EXCLUDED.marketing_consent,
        consent_source=EXCLUDED.consent_source, updated_at=NOW()
    """)

@router.get("/api/os/summary", dependencies=[Depends(operator_auth)])
async def summary():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await _sync_prospects(conn)
        rows = await conn.fetch("SELECT stage, count(*) AS n FROM os_prospects GROUP BY stage")
        pipeline = {r["stage"]: int(r["n"]) for r in rows}
        deals = await conn.fetch("""
          SELECT currency,
            count(*) AS total,
            COALESCE(sum(value_amount) FILTER (WHERE stage NOT IN ('won','lost')),0) AS pipeline_value,
            COALESCE(sum(value_amount) FILTER (WHERE stage='won'),0) AS won_value,
            count(*) FILTER (WHERE stage='won') AS won_count
          FROM os_deals GROUP BY currency ORDER BY currency
        """)
        replies = await conn.fetchrow("SELECT count(*) AS total, max(created_at) AS last_reply FROM os_replies")
        activity = await conn.fetchrow("SELECT max(created_at) AS last_activity FROM os_activities")
        subs = await conn.fetchrow("SELECT count(*) AS n FROM subscriptions WHERE status='active'")
        return {
          "prospects_total": sum(pipeline.values()), "pipeline": pipeline,
          "replies_total": int(replies["total"]), "deals_total": sum(int(d["total"]) for d in deals),
          "pipeline_value_by_currency": {d["currency"].strip(): float(d["pipeline_value"]) for d in deals},
          "won_value_by_currency": {d["currency"].strip(): float(d["won_value"]) for d in deals},
          "won_count": sum(int(d["won_count"]) for d in deals), "active_subscriptions": int(subs["n"]),
          "last_reply": replies["last_reply"].isoformat() if replies["last_reply"] else None,
          "last_activity": activity["last_activity"].isoformat() if activity["last_activity"] else None,
          "currency_note": "Deal values are grouped by currency; no FX conversion is performed."
        }

@router.get("/api/os/prospects", dependencies=[Depends(operator_auth)])
async def prospects(stage: str = "", q: str = "", limit: int = Query(100, ge=1, le=250)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await _sync_prospects(conn)
        rows = await conn.fetch("""
          SELECT id, lead_task_id, company, domain, email, source, segment, score,
                 stage, evidence, notes, marketing_consent, consent_source,
                 created_at, updated_at
          FROM os_prospects
          WHERE ($1='' OR stage=$1)
            AND ($2='' OR company ILIKE '%'||$2||'%' OR domain ILIKE '%'||$2||'%'
                 OR email ILIKE '%'||$2||'%')
          ORDER BY score DESC, updated_at DESC LIMIT $3
        """, stage, q.strip(), limit)
        return [dict(r) for r in rows]

@router.post("/api/os/prospects", dependencies=[Depends(operator_auth)])
async def create_prospect(body: ProspectCreate):
    domain = body.domain.strip().lower().removeprefix("https://").removeprefix("http://").strip("/")
    email = body.email.strip().lower()
    pool = await get_pool()
    async with pool.acquire() as conn:
        if domain:
            existing = await conn.fetchrow("SELECT id FROM os_prospects WHERE lower(domain)=lower($1) LIMIT 1", domain)
            if existing:
                raise HTTPException(status_code=409, detail=f"prospect already exists: {existing['id']}")
        row = await conn.fetchrow("""
          INSERT INTO os_prospects(company,domain,email,source,segment,score,notes,evidence)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) RETURNING id
        """, body.company.strip(), domain, email, body.source, body.segment,
             body.score, body.notes, json.dumps(body.evidence))
        await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'created',$2)",
                           row["id"], "Prospect added from " + body.source)
        return {"id": row["id"], "status": "created"}

@router.patch("/api/os/prospects/{prospect_id}", dependencies=[Depends(operator_auth)])
async def update_prospect(prospect_id: int, body: ProspectPatch):
    fields = body.model_fields_set
    if "stage" in fields and body.stage not in STAGES:
        raise HTTPException(status_code=400, detail="invalid pipeline stage")
    if body.marketing_consent is True and not (body.consent_source or "").strip():
        raise HTTPException(status_code=400, detail="record the exact consent source before enabling marketing consent")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id,lead_task_id FROM os_prospects WHERE id=$1", prospect_id)
        if not row:
            raise HTTPException(status_code=404, detail="prospect not found")
        if "stage" in fields:
            await conn.execute("UPDATE os_prospects SET stage=$1,updated_at=NOW() WHERE id=$2", body.stage, prospect_id)
            await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'stage',$2)",
                               prospect_id, "Stage changed to " + str(body.stage))
        if "notes" in fields:
            await conn.execute("UPDATE os_prospects SET notes=$1,updated_at=NOW() WHERE id=$2", body.notes or "", prospect_id)
        if "marketing_consent" in fields:
            await conn.execute("""
              UPDATE os_prospects SET marketing_consent=$1, consent_source=$2,
                updated_at=NOW() WHERE id=$3
            """, bool(body.marketing_consent), body.consent_source if body.marketing_consent else None, prospect_id)
            if row["lead_task_id"]:
                await conn.execute("""
                  UPDATE lead_tasks SET marketing_consent=$1, consent_source=$2,
                    consent_at=CASE WHEN $1 THEN NOW() ELSE NULL END WHERE id=$3
                """, bool(body.marketing_consent), body.consent_source if body.marketing_consent else None, row["lead_task_id"])
        return {"status": "updated", "id": prospect_id}

def classify_reply(text: str) -> tuple[str, float, str, str]:
    value = text.lower()
    optout = ("unsubscribe", "remove me", "stop emailing", "stop contacting",
              "do not contact", "don't contact", "no further emails", "opt out")
    meeting = ("book a call", "schedule a call", "demo", "meeting", "available",
               "calendar", "let's talk", "lets talk")
    interested = ("interested", "tell me more", "send details", "pricing",
                  "proposal", "sounds good", "yes,")
    objection = ("budget", "too expensive", "already have", "not a priority",
                 "not now", "later", "contract", "procurement")
    negative = ("not interested", "no thanks", "not relevant", "we're all set", "we are all set")
    if any(x in value for x in optout):
        return "opt_out", 0.99, "Recipient asked not to be contacted again.", "Suppress immediately; do not send further marketing."
    if any(x in value for x in meeting):
        return "meeting_request", 0.94, "Recipient appears open to a meeting or demonstration.", "Reply personally with two specific time slots."
    if any(x in value for x in negative):
        return "not_interested", 0.94, "Recipient declined the offer.", "Mark lost; do not continue the sequence."
    if any(x in value for x in interested):
        return "interested", 0.86, "Recipient requested more information or commercial details.", "Respond with a concise offer and one clear next step."
    if any(x in value for x in objection):
        return "objection", 0.82, "Recipient raised a timing, budget or incumbent objection.", "Address the stated objection; do not pressure."
    if any(x in value for x in ("out of office", "on leave", "back on", "returning on")):
        return "out_of_office", 0.9, "Automated or temporary absence response.", "Set a human-reviewed follow-up date."
    return "needs_review", 0.55, "No high-confidence intent pattern matched.", "Review the message and choose the next action manually."

@router.post("/api/os/replies", dependencies=[Depends(operator_auth)])
async def log_reply(body: ReplyCreate):
    category, confidence, summary_text, action = classify_reply(body.body)
    pool = await get_pool()
    async with pool.acquire() as conn:
        prospect = None
        if body.prospect_id:
            prospect = await conn.fetchrow("SELECT * FROM os_prospects WHERE id=$1", body.prospect_id)
        if not prospect:
            prospect = await conn.fetchrow("""
              SELECT * FROM os_prospects
              WHERE lower(email)=lower($1) OR ($2<>'' AND lower(domain)=lower($2))
              ORDER BY updated_at DESC LIMIT 1
            """, body.email.strip(), body.domain.strip().lower())
        pid = prospect["id"] if prospect else None
        row = await conn.fetchrow("""
          INSERT INTO os_replies(prospect_id,sender_email,subject,body,channel,category,confidence,summary,next_action)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id
        """, pid, body.email.strip().lower(), body.subject, body.body, body.channel,
             category, confidence, summary_text, action)
        if pid:
            stage = {"meeting_request":"meeting","interested":"replied",
                     "objection":"replied","not_interested":"lost",
                     "out_of_office":"contacted","opt_out":"suppressed"}.get(category)
            if stage:
                await conn.execute("UPDATE os_prospects SET stage=$1,marketing_consent=CASE WHEN $1='suppressed' THEN FALSE ELSE marketing_consent END,updated_at=NOW() WHERE id=$2", stage, pid)
                await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'reply',$2)",
                                   pid, category + ": " + summary_text)
            if category == "opt_out":
                await conn.execute("UPDATE os_prospects SET marketing_consent=FALSE,consent_source=NULL WHERE id=$1", pid)
                if prospect["lead_task_id"]:
                    await conn.execute("""
                      UPDATE lead_tasks SET status='suppressed', marketing_consent=FALSE,
                        consent_source=NULL, consent_at=NULL,
                        metadata=jsonb_set(COALESCE(metadata,'{}'::jsonb),'{reason}',to_jsonb($1::text))
                      WHERE id=$2
                    """, "reply_opt_out", prospect["lead_task_id"])
        return {"id": row["id"], "prospect_id": pid, "category": category,
                "confidence": confidence, "summary": summary_text, "next_action": action}

@router.get("/api/os/replies", dependencies=[Depends(operator_auth)])
async def replies(limit: int = Query(50, ge=1, le=200)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
          SELECT r.id,r.sender_email,r.subject,r.body,r.channel,r.category,
                 r.confidence,r.summary,r.next_action,r.created_at,
                 p.id AS prospect_id,p.company,p.domain
          FROM os_replies r LEFT JOIN os_prospects p ON p.id=r.prospect_id
          ORDER BY r.created_at DESC LIMIT $1
        """, limit)
        return [dict(r) for r in rows]

@router.post("/api/os/prospects/{prospect_id}/draft", dependencies=[Depends(operator_auth)])
async def outreach_draft(prospect_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        p = await conn.fetchrow("SELECT * FROM os_prospects WHERE id=$1", prospect_id)
        if not p:
            raise HTTPException(status_code=404, detail="prospect not found")
        evidence = p["evidence"] if isinstance(p["evidence"], dict) else {}
        signal_list = evidence.get("signals", [])
        proof = evidence.get("exposed_api_url") or evidence.get("staging_host") or ""
        subject = f"A practical idea for {p['company']}"
        body = (f"Hi {p['company']},\n\n"
                "I came across your company while researching teams in your space. "
                "Mellenth works across intelligence, security and automation.\n\n")
        if proof:
            body += f"One public signal worth reviewing: {proof}\n\n"
        if signal_list:
            body += "Observed public signals: " + ", ".join(str(x) for x in signal_list) + ".\n\n"
        body += ("If improving this area is on your roadmap, I can share a short, "
                 "evidence-led assessment and a practical next step. Would a brief "
                 "conversation be useful?\n\nRegards,\nMellenth\nhttps://mellenth.tech")
        mailto = ""
        if p["email"]:
            mailto = "mailto:" + quote(p["email"]) + "?subject=" + quote(subject) + "&body=" + quote(body)
        return {"subject": subject, "body": body, "mailto": mailto,
                "marketing_consent": bool(p["marketing_consent"]),
                "send_policy": "Draft only. Review recipient, evidence and applicable contact rules before sending."}

@router.get("/api/os/deals", dependencies=[Depends(operator_auth)])
async def deals():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
          SELECT d.*,p.company,p.domain FROM os_deals d
          JOIN os_prospects p ON p.id=d.prospect_id
          ORDER BY d.updated_at DESC LIMIT 200
        """)
        return [dict(r) for r in rows]

@router.post("/api/os/deals", dependencies=[Depends(operator_auth)])
async def create_deal(body: DealCreate):
    if body.stage not in {"discovery","qualified","proposal","negotiation","won","lost"}:
        raise HTTPException(status_code=400, detail="invalid deal stage")
    close_date = date.fromisoformat(body.expected_close) if body.expected_close else None
    pool = await get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchrow("SELECT id FROM os_prospects WHERE id=$1", body.prospect_id)
        if not exists:
            raise HTTPException(status_code=404, detail="prospect not found")
        row = await conn.fetchrow("""
          INSERT INTO os_deals(prospect_id,offer,value_amount,currency,stage,expected_close,payment_url,notes)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id
        """, body.prospect_id, body.offer, body.value_amount, body.currency.upper(),
             body.stage, close_date, body.payment_url, body.notes)
        await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'deal',$2)",
                           body.prospect_id, "Deal created: " + body.offer)
        return {"id": row["id"], "status": "created"}

@router.patch("/api/os/deals/{deal_id}", dependencies=[Depends(operator_auth)])
async def update_deal(deal_id: int, body: DealPatch):
    fields = body.model_fields_set
    if "stage" in fields and body.stage not in {"discovery","qualified","proposal","negotiation","won","lost"}:
        raise HTTPException(status_code=400, detail="invalid deal stage")
    close_date = date.fromisoformat(body.expected_close) if body.expected_close else None
    pool = await get_pool()
    async with pool.acquire() as conn:
        d = await conn.fetchrow("SELECT id,prospect_id FROM os_deals WHERE id=$1", deal_id)
        if not d:
            raise HTTPException(status_code=404, detail="deal not found")
        if "stage" in fields:
            await conn.execute("UPDATE os_deals SET stage=$1,updated_at=NOW() WHERE id=$2", body.stage, deal_id)
            await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'deal_stage',$2)",
                               d["prospect_id"], "Deal stage changed to " + str(body.stage))
        if "value_amount" in fields:
            await conn.execute("UPDATE os_deals SET value_amount=$1,updated_at=NOW() WHERE id=$2", body.value_amount, deal_id)
        if "expected_close" in fields:
            await conn.execute("UPDATE os_deals SET expected_close=$1,updated_at=NOW() WHERE id=$2", close_date, deal_id)
        if "payment_url" in fields:
            await conn.execute("UPDATE os_deals SET payment_url=$1,updated_at=NOW() WHERE id=$2", body.payment_url or "", deal_id)
        if "notes" in fields:
            await conn.execute("UPDATE os_deals SET notes=$1,updated_at=NOW() WHERE id=$2", body.notes or "", deal_id)
        return {"status":"updated","id":deal_id}

@router.post("/api/os/prospects/{prospect_id}/activity", dependencies=[Depends(operator_auth)])
async def add_activity(prospect_id: int, payload: dict[str, Any]):
    detail = str(payload.get("detail", "")).strip()[:4000]
    if not detail:
        raise HTTPException(status_code=400, detail="activity detail required")
    pool = await get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchrow("SELECT id FROM os_prospects WHERE id=$1", prospect_id)
        if not exists:
            raise HTTPException(status_code=404, detail="prospect not found")
        await conn.execute("INSERT INTO os_activities(prospect_id,kind,detail) VALUES($1,'note',$2)",
                           prospect_id, detail)
        return {"status":"recorded"}
