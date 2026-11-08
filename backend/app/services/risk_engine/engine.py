"""CyberShield AI — Deterministic Risk Engine Implementation (Part 15)

Evaluates standardized evidence collections through strictly deterministic,
auditable, and explainable rule sets. Guarantees that identical inputs yield
identical verdicts, prevents AI opinions from overstepping into authoritative
malice, and accurately reflects missing evidence.
"""

from typing import Optional, List
from app.schemas.evidence import EvidenceCollection
from app.schemas.risk import DeterministicRiskResult
from app.services.severity.classifier import classify_indicators
from app.services.risk_engine.rules import evaluate_rules


def evaluate_risk(collection: EvidenceCollection) -> DeterministicRiskResult:
    """Execute deterministic risk evaluation on a standardized evidence collection.
    
    Args:
        collection: Standardized evidence items, coverage audit, and limitations.
        
    Returns:
        DeterministicRiskResult containing 5-tier classification, numeric score (or None),
        explainable summary, triggered rules, and contributing factors.
    """
    # 1. Classify indicators (Severity & Authority)
    classified = classify_indicators(collection.items)

    # 2. Check for conflicting evidence
    has_conflicts = any(it.is_conflicting for it in collection.items)
    conflict_notes = None
    if has_conflicts:
        conflict_details = [it.conflict_details for it in collection.items if it.conflict_details]
        conflict_notes = "; ".join(set(conflict_details)) if conflict_details else "Conflicting indicator signals observed."

    # 3. Evaluate deterministic rules
    (
        classification,
        score,
        confidence,
        triggered_rules,
        contributing_factors,
        explanation,
        summary,
    ) = evaluate_rules(collection, classified)

    # 4. Assemble result
    return DeterministicRiskResult(
        classification=classification,
        score=score,
        confidence=confidence,
        method="deterministic_rule_engine_v1",
        explanation=explanation,
        summary=summary,
        contributing_factors=contributing_factors,
        triggered_rules=triggered_rules,
        coverage_ratio=collection.coverage.coverage_ratio,
        has_conflicting_evidence=has_conflicts,
        conflict_notes=conflict_notes,
        limitations=list(collection.limitations),
    )

