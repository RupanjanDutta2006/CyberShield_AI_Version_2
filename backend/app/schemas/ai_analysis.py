"""CyberShield AI — AI Scam & Message Analysis Schemas

Shared contract for Member 2 (AI Developer & Scam Intelligence Engineer).
"""

from typing import Optional, List
from pydantic import BaseModel, Field


class ObservedIndicator(BaseModel):
    """An individual social-engineering indicator identified in message content."""
    indicator: str = Field(..., description="Name/category of the observed indicator")
    evidence: str = Field(..., description="Quoted or summarized evidence from the input")
    reason: str = Field(..., description="Why this indicator is considered suspicious")


class ExtractedIndicators(BaseModel):
    """Digital artifacts extracted from submitted text."""
    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    domains: List[str] = Field(default_factory=list, description="Extracted domain names")
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone numbers")


class MessageAnalysisRequest(BaseModel):
    """Client request model for analyzing scam messages, emails, or SMS.
    Supports both Member 1 (`message_text`) and Member 2 (`message`) contracts.
    """
    message_text: Optional[str] = Field(
        default=None,
        min_length=5,
        max_length=10000,
        description="Untrusted email, SMS, or notification text to analyze (Member 1 format)"
    )
    message: Optional[str] = Field(
        default=None,
        min_length=5,
        max_length=10000,
        description="Untrusted email, SMS, or notification text to analyze (Member 2 format)"
    )
    sender_hint: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Optional sender address or caller ID if available"
    )
    message_type: Optional[str] = Field(
        default="other",
        description="Optional message contextual type (sms, email, job_offer, etc.)"
    )

    def get_text(self) -> str:
        text = (self.message_text if self.message_text is not None else self.message) or ""
        text = text.strip()
        if not text or len(text) < 5:
            raise ValueError("Either 'message_text' or 'message' must be provided with at least 5 characters.")
        return text


class MessageAnalysisResponse(BaseModel):
    """Structured response contract returned by the AI Scam Analysis module."""
    category: str = Field(
        ...,
        description="Detected scam category (e.g. possible_phishing, credential_harvesting, impersonation)"
    )
    risk_level: str = Field(
        ...,
        description="AI suggested risk tier (e.g. low_risk, suspicious, high_risk)"
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0 (if calibrated)"
    )
    observed_indicators: List[ObservedIndicator] = Field(
        default_factory=list,
        description="Specific social engineering indicators identified"
    )
    extracted_indicators: ExtractedIndicators = Field(
        default_factory=ExtractedIndicators,
        description="Structured indicators extracted for potential downstream URL investigation"
    )
    explanation: str = Field(
        ...,
        description="Plain-language, non-technical explanation grounded strictly in evidence"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable protective steps for the user"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit boundaries (e.g. text alone does not verify sender identity)"
    )
    analysis_mode: str = Field(
        default="HEURISTIC_ONLY",
        description="Mode of analysis: 'REAL_AI', 'HEURISTIC_ONLY', 'UNAVAILABLE', or 'FAILED' (B5-F04)"
    )

