"""CyberShield AI — Evidence Service Package (Part 13)

Provides standardized evidence collection, normalization, deduplication,
and coverage accounting across all security investigation modules.
"""

from app.schemas.evidence import (
    CheckStatus,
    EvidenceAuthority,
    StandardSeverity,
    EvidenceCategory,
    StandardizedEvidenceItem,
    EvidenceCoverage,
    EvidenceCollection,
)
from app.services.evidence.normalizer import (
    normalize_evidence,
    redact_sensitive_url_and_params,
    map_severity_to_standard,
)

__all__ = [
    "CheckStatus",
    "EvidenceAuthority",
    "StandardSeverity",
    "EvidenceCategory",
    "StandardizedEvidenceItem",
    "EvidenceCoverage",
    "EvidenceCollection",
    "normalize_evidence",
    "redact_sensitive_url_and_params",
    "map_severity_to_standard",
]

