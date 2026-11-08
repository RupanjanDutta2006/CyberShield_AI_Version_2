"""CyberShield AI — Part 12: HTTP Security Headers Analysis Models

Data models and schemas for passive HTTP security configuration analysis.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.common import TechnicalFinding, TechnicalLimitation
from app.schemas.url_scan import SecurityHeaderFindingDetails


class HeaderEvaluationStatus(str, Enum):
    """Quality and compliance status of an HTTP security header."""
    VALID = "VALID"
    WEAK = "WEAK"
    MALFORMED = "MALFORMED"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"


class SingleHeaderAnalysis(BaseModel):
    """Evaluation result for an individual HTTP security header."""
    header_name: str = Field(..., description="Canonical HTTP header name")
    status: HeaderEvaluationStatus = Field(..., description="Evaluation status")
    is_present: bool = Field(default=False, description="Whether the header was present in the response")
    raw_value: Optional[str] = Field(default=None, description="Observed header value")
    explanation: str = Field(default="", description="Technical rationale for the evaluation")
    details: Dict[str, Any] = Field(default_factory=dict, description="Parsed directives and parameters")


class SecurityHeaderAnalysisResult(BaseModel):
    """Complete structured findings from HTTP security header analysis (Part 12)."""
    target_url: str = Field(..., description="Target URL analyzed")
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    is_reachable: bool = Field(default=True, description="Whether endpoint was reachable")
    hsts: SingleHeaderAnalysis = Field(..., description="Strict-Transport-Security analysis")
    csp: SingleHeaderAnalysis = Field(..., description="Content-Security-Policy analysis")
    x_content_type_options: SingleHeaderAnalysis = Field(..., description="X-Content-Type-Options analysis")
    x_frame_options: SingleHeaderAnalysis = Field(..., description="X-Frame-Options analysis")
    referrer_policy: SingleHeaderAnalysis = Field(..., description="Referrer-Policy analysis")
    server_banner: Optional[str] = Field(default=None, description="Observed Server or X-Powered-By banner")
    additional_headers: Dict[str, str] = Field(default_factory=dict, description="Other observed security-relevant headers")
    findings: List[TechnicalFinding] = Field(default_factory=list, description="Structured technical findings")
    limitations: List[TechnicalLimitation] = Field(default_factory=list, description="Documented inspection limitations")

    def to_security_header_finding_details(self) -> SecurityHeaderFindingDetails:
        """Convert into backward-compatible SecurityHeaderFindingDetails for report schemas."""
        missing = []
        if not self.hsts.is_present:
            missing.append("Strict-Transport-Security")
        if not self.csp.is_present:
            missing.append("Content-Security-Policy")
        if not self.x_content_type_options.is_present:
            missing.append("X-Content-Type-Options")
        if not self.x_frame_options.is_present:
            missing.append("X-Frame-Options")

        return SecurityHeaderFindingDetails(
            hsts_present=self.hsts.is_present if self.is_reachable else None,
            csp_present=self.csp.is_present if self.is_reachable else None,
            x_frame_options_present=self.x_frame_options.is_present if self.is_reachable else None,
            x_content_type_options_present=self.x_content_type_options.is_present if self.is_reachable else None,
            missing_recommended_headers=missing,
            server_banner=self.server_banner
        )

