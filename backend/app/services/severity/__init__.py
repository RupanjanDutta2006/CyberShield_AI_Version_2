"""CyberShield AI — Severity Classification Package (Part 14)

Provides indicator severity rating, evidence authority classification,
deduplication, and corroboration calibration.
"""

from app.services.severity.models import (
    ClassifiedIndicator,
    IndicatorClassificationResult,
)
from app.services.severity.classifier import (
    classify_indicators,
    derive_underlying_issue_key,
    BASE_WEIGHTS,
    AUTHORITY_MULTIPLIERS,
)

__all__ = [
    "ClassifiedIndicator",
    "IndicatorClassificationResult",
    "classify_indicators",
    "derive_underlying_issue_key",
    "BASE_WEIGHTS",
    "AUTHORITY_MULTIPLIERS",
]

