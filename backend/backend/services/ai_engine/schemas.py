"""Pydantic v2 schemas for the AI message analysis API."""

import unicodedata
from enum import Enum
from typing import List
from pydantic import BaseModel, Field, field_validator


class MessageTypeEnum(str, Enum):
    """Allowed message types for incoming submissions."""

    SMS = "sms"
    EMAIL = "email"
    JOB_OFFER = "job_offer"
    INTERNSHIP_OFFER = "internship_offer"
    OTHER = "other"


class RiskLevelEnum(str, Enum):
    """Allowed risk levels for threat assessment.

    Notice: 'confirmed_malicious' is strictly excluded as LLM predictions
    alone are uncalibrated and cannot definitively confirm maliciousness.
    """

    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    INCONCLUSIVE = "inconclusive"


class CategoryEnum(str, Enum):
    """Agreed threat classification categories."""

    POSSIBLE_PHISHING = "possible_phishing"
    POSSIBLE_JOB_SCAM = "possible_job_scam"
    POSSIBLE_IMPERSONATION = "possible_impersonation"
    POSSIBLE_PAYMENT_SCAM = "possible_payment_scam"
    POSSIBLE_CREDENTIAL_THEFT = "possible_credential_theft"
    SOCIAL_ENGINEERING = "social_engineering"
    POTENTIALLY_BENIGN = "potentially_benign"
    INCONCLUSIVE = "inconclusive"


class AnalyzeMessageRequest(BaseModel):
    """Input request schema for message analysis."""

    message: str = Field(
        ...,
        description="The raw text content of the message to be analyzed.",
        min_length=1,
        max_length=15000,
        examples=["Your bank account is blocked. Share your OTP immediately."],
    )
    message_type: MessageTypeEnum = Field(
        default=MessageTypeEnum.OTHER,
        description="The medium or contextual classification of the message.",
        examples=["sms"],
    )

    @field_validator("message")
    @classmethod
    def validate_and_normalize_message(cls, value: str) -> str:
        """Normalize Unicode, strip excessive padding, and reject whitespace-only strings."""
        if not value:
            raise ValueError("Message cannot be empty.")

        # Normalize unicode characters (NFKC)
        normalized = unicodedata.normalize("NFKC", value).strip()

        # Reject if effectively blank after stripping whitespace
        if not normalized:
            raise ValueError("Message cannot consist solely of whitespace.")

        if len(normalized) > 15000:
            raise ValueError("Message exceeds maximum allowed length of 15,000 characters.")

        return normalized


class ObservedIndicator(BaseModel):
    """Ground-truth observed indicator grounded in the message text."""

    indicator: str = Field(
        ...,
        description="Name of the observed suspicious trait or behavior.",
        examples=["OTP request"],
    )
    evidence: str = Field(
        ...,
        description="Exact quotation from the submitted message supporting this indicator.",
        examples=["Share your OTP immediately."],
    )
    reason: str = Field(
        ...,
        description="Explanation of why this observed quote is considered risky or suspicious.",
        examples=["The message requests sensitive authentication information."],
    )


class ExtractedIndicators(BaseModel):
    """Deterministically extracted technical indicators."""

    urls: List[str] = Field(
        default_factory=list,
        description="Deduplicated list of exact extracted URL strings.",
    )
    domains: List[str] = Field(
        default_factory=list,
        description="Deduplicated list of extracted hostnames/domains.",
    )
    emails: List[str] = Field(
        default_factory=list,
        description="Deduplicated list of extracted email addresses.",
    )
    phone_numbers: List[str] = Field(
        default_factory=list,
        description="Deduplicated list of extracted phone numbers.",
    )


class AnalyzeMessageResponse(BaseModel):
    """Standardized response schema returned to clients and services."""

    category: CategoryEnum = Field(
        ...,
        description="Primary detected threat classification.",
        examples=["possible_phishing"],
    )
    risk_level: RiskLevelEnum = Field(
        ...,
        description="Estimated threat severity level.",
        examples=["suspicious"],
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Uncalibrated model confidence score between 0.0 and 1.0.",
        examples=[0.85],
    )
    observed_indicators: List[ObservedIndicator] = Field(
        default_factory=list,
        description="Observed indicators backed strictly by quotes from the source message.",
    )
    extracted_indicators: ExtractedIndicators = Field(
        default_factory=ExtractedIndicators,
        description="Deterministically extracted technical artifacts (URLs, domains, emails, phones).",
    )
    explanation: str = Field(
        ...,
        description="Concise evidence-based explanation of the analysis findings.",
        examples=["The message contains a suspicious authentication request."],
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable guidance for the recipient.",
        examples=[
            "Do not share your OTP.",
            "Contact the organization using an independently verified channel.",
        ],
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit limitations and caveats regarding the analysis.",
        examples=["The message alone cannot establish the sender's identity."],
    )
