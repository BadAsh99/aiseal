#!/usr/bin/env python3
"""
AISeal TrustScan API — v1
Versioned, authenticated REST API for the AISeal scanner engine.
"""

import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

from models import ScanRequest, ScanResponse
from scanner import run_scan, OWASP_CATEGORIES

load_dotenv()

VALID_KEYS: set[str] = set(
    k.strip() for k in os.environ.get("AISEAL_API_KEYS", "").split(",") if k.strip()
)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AISeal TrustScan API",
    description="OWASP LLM Top 10 scanning. TrustScore 0–100. Machine-readable AI trust signal.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://aiseal.ai", "http://localhost:3000"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


def verify_key(x_aiseal_key: str = Header(..., description="Your AISeal API key")):
    if not VALID_KEYS:
        raise HTTPException(status_code=500, detail="API key store not configured")
    if x_aiseal_key not in VALID_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_aiseal_key


@app.get("/v1/health", tags=["System"])
async def health():
    """Service health check. No auth required."""
    return {
        "status": "online",
        "version": "1.0.0",
        "categories": len(OWASP_CATEGORIES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/v1/scan", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("30/minute")
async def scan(
    request: Request,
    body: ScanRequest,
    key: str = Depends(verify_key),
):
    """
    Run a TrustScan against a prompt.

    Returns a TrustScore (0–100) and per-category findings across the OWASP LLM Top 10.
    Scores below 70 indicate elevated risk. Scores below 50 indicate critical exposure.

    **Rate limit:** 30 requests/minute per IP.
    """
    prompt = body.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

    start = time.time()
    score, findings = run_scan(prompt)
    latency_ms = round((time.time() - start) * 1000)

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        score=score,
        findings=findings,
        model=body.model,
        scenario=body.scenario,
        prompt_length=len(prompt),
        categories_checked=len(OWASP_CATEGORIES),
        latency_ms=latency_ms,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
