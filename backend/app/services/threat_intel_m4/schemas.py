from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class NormalizedThreatIndicator(BaseModel):
    provider: str
    indicator_type: str  # 'url', 'domain', 'ip'
    indicator_value: str
    status: str  # 'match_found', 'clean', 'not_configured', 'unavailable', 'error'
    matched: bool = False
    verified: bool = False
    reference: Optional[str] = None
    details: Dict[str, Any] = {}
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class AggregatedReputationAssessment(BaseModel):
    risk_level: str  # 'Critical', 'High', 'Medium', 'Low', 'Unknown'
    risk_score: int  # 0 to 100
    summary: str
    evidence: List[str]
    recommendations: List[str]
    indicators: List[NormalizedThreatIndicator]
