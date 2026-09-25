from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON, String, DateTime, Text, Integer, Float, Boolean


class UrlScan(SQLModel, table=True):
    __tablename__ = "url_scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(sa_column=Column(Text, nullable=False, index=True))
    risk_score: int = Field(sa_column=Column(Integer, nullable=False))
    verdict: str = Field(sa_column=Column(String(50), nullable=False))
    reasons: List[str] = Field(default=[], sa_column=Column(JSON, nullable=False))
    details: Dict[str, Any] = Field(default={}, sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime, default=datetime.utcnow, nullable=False)
    )


class EmailScan(SQLModel, table=True):
    __tablename__ = "email_scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    subject: str = Field(sa_column=Column(String(255), nullable=True))
    body_preview: str = Field(sa_column=Column(Text, nullable=False))
    phishing_likelihood: str = Field(sa_column=Column(String(50), nullable=False))
    score: int = Field(sa_column=Column(Integer, nullable=False))
    patterns_found: List[str] = Field(default=[], sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime, default=datetime.utcnow, nullable=False)
    )


class Report(SQLModel, table=True):
    __tablename__ = "reports"

    id: Optional[int] = Field(default=None, primary_key=True)
    type: str = Field(sa_column=Column(String(20), nullable=False))  # "url" or "email"
    content: str = Field(sa_column=Column(Text, nullable=False))
    notes: Optional[str] = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime, default=datetime.utcnow, nullable=False)
    )
