from pydantic import BaseModel
from typing import Literal, Optional
import uuid
from datetime import datetime


class NistMapping(BaseModel):
    functions: list[str]
    pillars: list[str]


class MitreMapping(BaseModel):
    id: str
    name: str


class Finding(BaseModel):
    category: str
    code: str
    status: Literal["pass", "fail", "warning"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    detail: str
    nist: Optional[NistMapping] = None
    mitre: Optional[list[MitreMapping]] = None


class ScanRequest(BaseModel):
    prompt: str
    model: str = "gpt-4o"
    scenario: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    score: int
    findings: list[Finding]
    model: str
    scenario: Optional[str]
    prompt_length: int
    categories_checked: int
    latency_ms: int
    timestamp: str
