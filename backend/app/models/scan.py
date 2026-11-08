"""Compatibility wrapper for Member 4 model imports."""
from app.database.models import (
    Base,
    Scan,
    IntelligenceResult,
    RiskReport,
    ScanEvent,
    generate_uuid,
    utc_now,
)

__all__ = [
    "Base",
    "Scan",
    "IntelligenceResult",
    "RiskReport",
    "ScanEvent",
    "generate_uuid",
    "utc_now",
]
