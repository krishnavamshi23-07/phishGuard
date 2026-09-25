from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl, Field


class UrlScanDetails(BaseModel):
    rule_score: int = Field(..., ge=0, le=100, description="Rule-based heuristic score (0-100)")
    ml_probability: float = Field(..., ge=0.0, le=1.0, description="Machine learning model predicted probability (0-1)")
    blocklist_hit: bool = Field(..., description="Whether domain matched a known blocklist")
    domain: str = Field(..., description="Target root domain")
    domain_age_days: int = Field(..., description="Estimated age of domain in days")


class UrlScanRequest(BaseModel):
    url: str = Field(..., example="https://example.com/login", description="URL to analyze")


class UrlScanResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Final fused risk score (0-100)")
    verdict: Literal["safe", "suspicious", "likely_phishing"]
    reasons: List[str]
    details: UrlScanDetails


class EmailScanRequest(BaseModel):
    subject: Optional[str] = Field(default="", example="Urgent: Verify your account")
    body: str = Field(..., example="Dear customer, your account will be suspended within 24 hours...")


class EmailScanResponse(BaseModel):
    phishing_likelihood: Literal["low", "medium", "high"]
    score: int = Field(..., ge=0, le=100)
    patterns_found: List[str]


class ReportRequest(BaseModel):
    type: Literal["url", "email"]
    content: str = Field(..., min_length=1)
    notes: Optional[str] = None


class ReportResponse(BaseModel):
    success: bool = True
