from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL or domain to analyze")


class MessageScanRequest(BaseModel):
    content: str = Field(..., min_length=3, max_length=50000, description="Email body, SMS, or message text")


class MessageIndicator(BaseModel):
    category: str
    severity: str
    description: str


class ProviderResultSchema(BaseModel):
    provider: str
    indicator_type: str
    indicator_value: str
    status: str  # 'match_found', 'clean', 'not_configured', 'unavailable', 'error'
    matched: bool
    verified: bool
    reference: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class RiskReportSchema(BaseModel):
    report_id: str
    summary: str
    evidence: List[str]
    recommendations: List[str]
    report_hash: str
    verification_status: str
    blockchain_tx: Optional[str] = None
    created_at: datetime


class ScanEventSchema(BaseModel):
    event_type: str
    description: str
    created_at: datetime


class ScanDetailResponse(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    normalized_target: Optional[str] = None
    domain: Optional[str] = None
    hostname: Optional[str] = None
    status: str
    risk_level: str
    risk_score: int
    created_at: datetime
    providers_checked: List[ProviderResultSchema]
    report: Optional[RiskReportSchema] = None
    events: List[ScanEventSchema] = []
    message_indicators: Optional[List[MessageIndicator]] = None
    analysis_engine: Optional[str] = None


class ScanListItem(BaseModel):
    id: str
    scan_type: str
    target: str
    status: str
    risk_level: str
    risk_score: int
    created_at: datetime
    report_hash: Optional[str] = None
    verification_status: Optional[str] = None


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanListItem]


class VerifyReportResponse(BaseModel):
    report_id: str
    stored_hash: str
    recalculated_hash: str
    is_valid: bool
    verification_status: str
    audit_notes: str
    blockchain_verified: bool
    blockchain_tx: Optional[str] = None


class ProviderStatusItem(BaseModel):
    provider_name: str
    category: str
    configured: bool
    status: str
    details: str
    env_variable: str


class SystemStatusResponse(BaseModel):
    status: str
    database_connected: bool
    database_type: str
    providers: List[ProviderStatusItem]
    app_version: str
    environment: str


class StatsOverviewResponse(BaseModel):
    total_scans: int
    malicious_count: int
    suspicious_count: int
    benign_count: int
    risk_distribution: Dict[str, int]
    recent_scans: List[ScanListItem]
