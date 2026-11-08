"""CyberShield AI — Report Generator Package (Part 16)

Provides unified threat report assembly, evidence-grounded recommendation generation,
and schema validation.
"""

from app.schemas.report import (
    ReportGenerationRequest,
    UnifiedThreatReport,
)
from app.services.report_generator.builder import (
    build_threat_report,
    assemble_unified_threat_report,
    generate_recommendations,
)

__all__ = [
    "ReportGenerationRequest",
    "UnifiedThreatReport",
    "build_threat_report",
    "assemble_unified_threat_report",
    "generate_recommendations",
]

