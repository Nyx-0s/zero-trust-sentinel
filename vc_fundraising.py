"""Founder-controlled venture fundraising pipeline for Mellenth.

Investor discovery records require public-source evidence. Contact addresses must
be published by the fund or supplied by the founder; the system never guesses.
Drafts are never sent until a founder explicitly approves that investor.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from db import get_pool
from mellenth_os import operator_auth, classify_reply

router = APIRouter()
VC_STAGES = {"new", "researching", "qualified", "draft_ready", "approved",
             "contacted", "replied", "meeting", "due_diligence", "passed",
             "committed", "suppressed"}

class InvestorCreate(BaseModel):
    firm: str = Field(min_length=1, max_length=180)
    domain: str = Field(default="", max_length=255)
    contact_name: str = Field(default="", max_length=180)
    role: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=255)
    source_url: str = Field(default="", max_length=1000)
    thesis: str = Field(default="", max_length=4000)
    stage_focus: str = Field(default="", max_length=500)
    geography: str = Field(default="", max_length=500)
    check_size: str = Field(default="", max_length=250)
    portfolio_signals: list[str] = Field(default_factory=list, max_length=30)
    evidence: dict[str, Any] = Field(default_factory=dict)
    notes: str = Field(default="", max_length=6000)

class InvestorPatch(BaseModel):
    stage: Optional[str] = None
    notes: Optional[str] = Field(default=None, max_length=6000)
    fit_score: Optional[int] = Field(default=None, ge=0, le=100)
    outreach_approved: Optional[bool] = None

class DraftRequest(BaseModel):
    subject: str = Field(default="", max_length=250)
    body: str = Field(default="", max_length=12000)

async def ensure_schema() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS os_investors (
          id BIGSERIAL PRIMARY KEY,
          firm TEXT NOT NULL,
          domain VARCHAR(255) NOT NULL DEFAULT '',
          contact_name TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT '',
          email VARCHAR(255) NOT NULL DEFAULT '',
          source_url TEXT NOT NULL DEFAULT '',
          thesis TEXT NOT NULL DEFAULT '',
          stage_focus TEXT NOT NULL DEFAULT '',
          geography TEXT NOT NULL DEFAULT '',
          check_size TEXT NOT NULL DEFAULT '',
          portfolio_signals JSONB NOT NULL DEFAULT '[]'::jsonb,
          evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
          notes TEXT NOT NULL DEFAULT '',
          fit_score INTEGER NOT NULL DEFAULT 0,
          stage VARCHAR(32) NOT NULL DEFAULT 'new',
          outreach_approved BOOLEAN NOT NULL DEFAULT FALSE,
          draft_subject TEXT NOT NULL DEFAULT '',
          draft_body TEXT NOT NULL DEFAULT '',
          draft_approved_at TIMESTAMPTZ,
          contacted_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE (firm, email)
        );
        CREATE INDEX IF NOT EXISTS os_investors_stage_idx ON os_investors(stage, fit_score DESC);
        CREATE INDEX IF NOT EXISTS os_investors_email_idx ON os_investors(lower(email));
        CREATE TABLE IF NOT EXISTS os_investor_replies (
          id BIGSERIAL PRIMARY KEY,
          investor_id BIGINT REFERENCES os_investors(id) ON DELETE SET NULL,
          sender_email VARCHAR(255) NOT NULL,
          external_id VARCHAR(255) UNIQUE,
          subject TEXT NOT NULL DEFAULT '',
          body TEXT NOT NULL,
          category VARCHAR(40) NOT NULL DEFAULT 'needs_review',
          confidence NUMERIC(4,3) NOT NULL DEFAULT 0.5,
          summary TEXT NOT NULL DEFAULT '',
          next_action TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS os_investor_replies_created_idx ON os_investor_replies(created_at DESC);
        """)

def _clean_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value).split("/")[0]
    return value[:255]

def _valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value.strip()))

@router.get("/fundraising")
async def fundraising_page():
    return FileResponse(Path(__file__).parent / "static" / "fundraising.html")

@router.get("/api/os/fundraising/summary", dependencies=[Depends(operator_auth)])
async def fundraising_summary():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT stage,count(*) n FROM os_investors GROUP BY stage")
        pipeline = {r["stage"]: int(r["n"]) for r in rows}
        replies = await conn.fetchrow("SELECT count(*) n FROM os_investor_replies")
        approved = await conn.fetchrow("SELECT count(*) n FROM os_investors WHERE outreach_approved=TRUE AND stage='approved'")
        return {"total": sum(pipeline.values()), "pipeline": pipeline,
                "replies": int(replies["n"]), "approved_to_contact": int(approved["n"])}

@router.get("/api/os/fundraising/investors", dependencies=[Depends(operator_auth)])
async def list_investors(stage: str = "", q: str = "", limit: int = Query(150, ge=1, le=300)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
          SELECT id,firm,domain,contact_name,role,email,source_url,thesis,stage_focus,
                 geography,check_size,portfolio_signals,evidence,notes,fit_score,stage,
                 outreach_approved,draft_subject,draft_body,draft_approved_at,
                 contacted_at,created_at,updated_at
          FROM os_investors
          WHERE ($1='' OR stage=$1)
            AND ($2='' OR firm ILIKE '%'||$2||'%' OR domain ILIKE '%'||$2||'%'
                 OR contact_name ILIKE '%'||$2||'%' OR email ILIKE '%'||$2||'%')
          ORDER BY fit_score DESC, updated_at DESC LIMIT $3
        """, stage, q.strip(), limit)
        return [dict(r) for r in rows]

@router.post("/api/os/fundraising/investors", dependencies=[Depends(operator_auth)])
async def add_investor(body: InvestorCreate):
    domain = _clean_domain(body.domain)
    email = body.email.strip().lower()
    if email and not _valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email")
    if email and not body.source_url.strip() and not body.evidence:
        raise HTTPException(status_code=400, detail="record a public source URL or evidence for the contact")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
          INSERT INTO os_investors
            (firm,domain,contact_name,role,email,source_url,thesis,stage_focus,
             geography,check_size,portfolio_signals,evidence,notes)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
          ON CONFLICT(firm,email) DO UPDATE SET
            domain=COALESCE(NULLIF(EXCLUDED.domain,''),os_investors.domain),
            source_url=COALESCE(NULLIF(EXCLUDED.source_url,''),os_investors.source_url),
            thesis=COALESCE(NULLIF(EXCLUDED.thesis,''),os_investors.thesis),
            stage_focus=COALESCE(NULLIF(EXCLUDED.stage_focus,''),os_investors.stage_focus),
            geography=COALESCE(NULLIF(EXCLUDED.geography,''),os_investors.geography),
            check_size=COALESCE(NULLIF(EXCLUDED.check_size,''),os_investors.check_size),
            portfolio_signals=EXCLUDED.portfolio_signals,
            evidence=EXCLUDED.evidence,
            updated_at=NOW()
          RETURNING id
        """, body.firm.strip(), domain, body.contact_name.strip(), body.role.strip(),
             email, body.source_url.strip(), body.thesis.strip(), body.stage_focus.strip(),
             body.geography.strip(), body.check_size.strip(), json.dumps(body.portfolio_signals),
             json.dumps(body.evidence), body.notes.strip())
        return {"id": row["id"], "status": "saved"}

@router.patch("/api/os/fundraising/investors/{investor_id}", dependencies=[Depends(operator_auth)])
async def update_investor(investor_id: int, body: InvestorPatch):
    fields = body.model_fields_set
    if "stage" in fields and body.stage not in VC_STAGES:
        raise HTTPException(status_code=400, detail="invalid investor stage")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM os_investors WHERE id=$1", investor_id)
        if not row:
            raise HTTPException(status_code=404, detail="investor not found")
        if "stage" in fields:
            await conn.execute("UPDATE os_investors SET stage=$1,updated_at=NOW() WHERE id=$2", body.stage, investor_id)
        if "notes" in fields:
            await conn.execute("UPDATE os_investors SET notes=$1,updated_at=NOW() WHERE id=$2", body.notes or "", investor_id)
        if "fit_score" in fields:
            await conn.execute("UPDATE os_investors SET fit_score=$1,updated_at=NOW() WHERE id=$2", body.fit_score, investor_id)
        if "outreach_approved" in fields:
            stage = "approved" if body.outreach_approved else "draft_ready"
            await conn.execute("""
              UPDATE os_investors SET outreach_approved=$1,
                stage=CASE WHEN $1 THEN 'approved' ELSE 'draft_ready' END,
                draft_approved_at=CASE WHEN $1 THEN NOW() ELSE NULL END,
                updated_at=NOW() WHERE id=$2
            """, bool(body.outreach_approved), investor_id)
        return {"id": investor_id, "status": "updated"}

@router.post("/api/os/fundraising/investors/{investor_id}/draft", dependencies=[Depends(operator_auth)])
async def draft_investor_outreach(investor_id: int):
    pool = await get_pool()
    async with pool.acquire() as conn:
        p = await conn.fetchrow("SELECT * FROM os_investors WHERE id=$1", investor_id)
        if not p:
            raise HTTPException(status_code=404, detail="investor not found")
        signals = p["portfolio_signals"] if isinstance(p["portfolio_signals"], list) else []
        evidence = p["evidence"] if isinstance(p["evidence"], dict) else {}
        subject = f"Mellenth | {p['firm']} and the future of operational intelligence"
        body = f"""Hello {p['contact_name'] or p['firm']} team,

I’m reaching out from Mellenth (mellenth.tech), an early-stage technology company working across three connected areas: Intelligence, Security and Automation.

I noticed {p['firm']}’s stated investment focus: {p['thesis'] or 'your published technology investment thesis'}. Our work may be relevant where that thesis intersects with {p['stage_focus'] or 'early-stage enterprise technology'}.

Mellenth is developing a portfolio of products spanning external security intelligence, permission-bounded AI workflows and institutional automation. We are seeking a conversation with investors who understand technically ambitious, execution-led software businesses.

A few current product references:
- Zero-Trust Sentinel — external exposure intelligence and security operations.
- ConsentArk — permission-bounded AI workflows and auditable automation.
- Prometheus — strategic intelligence experience.

Relevant public evidence: {p['source_url'] or 'We can share product and technical materials directly.'}
Portfolio/context signals recorded: {', '.join(str(x) for x in signals) if signals else 'No portfolio signal recorded yet.'}

If this fits your current investment mandate, would you be open to a short introductory conversation? I can share a concise deck, product walkthrough and current operating metrics.

Regards,
Founder
Mellenth
https://mellenth.tech

If this is outside your mandate, let me know and I will not follow up."""
        await conn.execute("""
          UPDATE os_investors SET draft_subject=$1,draft_body=$2,
            outreach_approved=FALSE,stage='draft_ready',updated_at=NOW()
          WHERE id=$3
        """, subject, body, investor_id)
        return {"subject": subject, "body": body, "status": "draft_ready",
                "send_policy": "Not sent. Founder must review facts, recipient and draft, then explicitly approve."}

@router.get("/api/os/fundraising/replies", dependencies=[Depends(operator_auth)])
async def investor_replies(limit: int = Query(100, ge=1, le=200)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
          SELECT r.*,i.firm,i.contact_name FROM os_investor_replies r
          LEFT JOIN os_investors i ON i.id=r.investor_id
          ORDER BY r.created_at DESC LIMIT $1
        """, limit)
        return [dict(r) for r in rows]


async def record_investor_reply(sender_email: str, subject: str, body: str, external_id: Optional[str] = None) -> Optional[dict[str, Any]]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        investor = await conn.fetchrow("SELECT id,firm FROM os_investors WHERE lower(email)=lower($1) LIMIT 1", sender_email.strip())
        if not investor:
            return None
        if external_id:
            duplicate = await conn.fetchrow("SELECT id,category FROM os_investor_replies WHERE external_id=$1", external_id)
            if duplicate:
                return {"id": duplicate["id"], "category": duplicate["category"], "duplicate": True}
        category, confidence, summary, next_action = classify_reply(body)
        row = await conn.fetchrow("INSERT INTO os_investor_replies(investor_id,sender_email,external_id,subject,body,category,confidence,summary,next_action) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id", investor["id"], sender_email.strip().lower(), external_id, subject[:500], body[:20000], category, confidence, summary, next_action)
        stage = {"meeting_request":"meeting", "interested":"replied", "objection":"replied", "not_interested":"passed", "opt_out":"suppressed", "out_of_office":"contacted"}.get(category, "replied")
        await conn.execute("UPDATE os_investors SET stage=$1,outreach_approved=FALSE,updated_at=NOW() WHERE id=$2", stage, investor["id"])
        return {"id":row["id"],"investor_id":investor["id"],"firm":investor["firm"],"category":category,"confidence":confidence,"summary":summary,"next_action":next_action,"duplicate":False}

@router.post("/api/os/fundraising/replies", dependencies=[Depends(operator_auth)])
async def log_investor_reply(body: dict[str, Any]):
    sender = str(body.get("email", "")).strip().lower()
    message = str(body.get("body", "")).strip()
    if not _valid_email(sender) or not message:
        raise HTTPException(status_code=400, detail="valid email and reply body are required")
    result = await record_investor_reply(sender, str(body.get("subject", "")), message, str(body.get("external_id", "")) or None)
    if not result:
        raise HTTPException(status_code=404, detail="no investor matched this sender")
    return result
