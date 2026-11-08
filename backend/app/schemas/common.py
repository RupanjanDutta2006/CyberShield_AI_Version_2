"""CyberShield AI — Common Enums and Base Models

Shared vocabulary and base data models used across all contracts.
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class RiskClassification(str, Enum):
    """Standardized 5-tier risk classifications per problem statement."""
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"


class ScanType(str, Enum):
    """Supported target intake types."""
    URL = "url"
    DOMAIN = "domain"
    MESSAGE = "message"


class AnalysisStatus(str, Enum):
    """Status of technical investigation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    """Severity ratings for technical and intelligence findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(str, Enum):
    """Blockchain integrity status."""
    NOT_REGISTERED = "not_registered"
    PENDING_TRANSACTION = "pending_transaction"
    VERIFIED_VALID = "verified_valid"
    VERIFIED_TAMPERED = "verified_tampered"
    NOT_FOUND = "not_found"
    SIMULATED_VALID = "simulated_valid"
    SIMULATED_TAMPERED = "simulated_tampered"
    UNAVAILABLE = "unavailable"


class TechnicalFinding(BaseModel):
    """Individual security finding with supporting technical evidence."""
    module: str = Field(..., description="Module generating finding, e.g. dns, tls, headers")
    check_name: str = Field(..., description="Identifier of the specific check")
    severity: FindingSeverity = Field(..., description="Severity rating")
    title: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed description")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Technical evidence key-value data")
    remediation: Optional[str] = Field(default=None, description="Recommended remediation action")


class TechnicalLimitation(BaseModel):
    """Documentation of unavailable checks or inspection limits."""
    module: str = Field(..., description="Affected module")
    reason: str = Field(..., description="Why the check could not be completed or was omitted")
    impact: str = Field(..., description="Impact on overall risk confidence")

