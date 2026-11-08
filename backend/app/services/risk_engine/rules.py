"""CyberShield AI — Deterministic Risk Rules Specification (Part 15)

Defines explicit, auditable risk aggregation rules, condition evaluation logic,
and classification policies.
"""

from typing import List, Tuple, Optional
from app.schemas.common import RiskClassification
from app.schemas.evidence import (
    StandardSeverity,
    EvidenceAuthority,
    EvidenceCategory,
    EvidenceCollection,
)
from app.schemas.risk import TriggeredRule, ContributingFactor
from app.services.severity.models import IndicatorClassificationResult, ClassifiedIndicator


def evaluate_rules(
    collection: EvidenceCollection,
    classified: IndicatorClassificationResult,
) -> Tuple[RiskClassification, Optional[int], Optional[float], List[TriggeredRule], List[ContributingFactor], str, str]:
    """Execute deterministic risk evaluation rules against classified indicators and coverage.
    
    Returns:
        (classification, score, confidence, triggered_rules, contributing_factors, explanation, summary)
    """
    triggered_rules: List[TriggeredRule] = []
    contributing_factors: List[ContributingFactor] = []

    # Calculate raw score from deduplicated indicator effective weights
    raw_score = sum(ind.effective_weight for ind in classified.classified_indicators)
    raw_score_int = min(100, int(round(raw_score)))

    # Coverage ratio from evidence collection
    coverage_ratio = collection.coverage.coverage_ratio

    # Check for empty evidence
    is_empty_evidence = (len(collection.items) == 0 and len(collection.coverage.completed) == 0)
    
    # Check for critical DNS failure
    is_dns_failed_or_unavailable = (
        "dns_investigation" in collection.coverage.failed
        or "dns_investigation" in collection.coverage.unavailable
    )

    # Check for critical redirect failure with no other data
    is_redirect_failed = "redirect_analysis" in collection.coverage.failed

    # Has authoritative malicious match
    has_authoritative_threat = classified.has_authoritative_malicious_evidence

    # Build contributing factors for non-informational indicators
    for ind in classified.classified_indicators:
        if ind.severity in (StandardSeverity.LOW, StandardSeverity.MEDIUM, StandardSeverity.HIGH):
            contributing_factors.append(ContributingFactor(
                indicator_id=ind.indicator_id,
                title=ind.title,
                severity=ind.severity,
                authority=ind.authority,
                weight_contribution=ind.effective_weight,
                reason=ind.explanation,
            ))

    # -------------------------------------------------------------------------
    # RULE-01: Inconclusive on Empty Evidence or Critical Availability Failure
    # -------------------------------------------------------------------------
    rule_01_matched = False
    rule_01_reason = ""
    if not has_authoritative_threat:
        if is_empty_evidence:
            rule_01_matched = True
            rule_01_reason = "No investigation checks could be executed; target yielded empty evidence."
        elif is_dns_failed_or_unavailable and len(contributing_factors) == 0:
            rule_01_matched = True
            rule_01_reason = "Critical DNS investigation failed or was unavailable; destination could not be resolved."
        elif coverage_ratio < 0.40 and len(contributing_factors) == 0:
            rule_01_matched = True
            rule_01_reason = f"Investigation coverage is insufficient ({int(coverage_ratio * 100)}% completed checks)."
        elif is_redirect_failed and len(collection.coverage.completed) <= 1 and len(contributing_factors) == 0:
            rule_01_matched = True
            rule_01_reason = "Redirect tracing failed due to network connection errors and no secondary checks completed."

    triggered_rules.append(TriggeredRule(
        rule_id="RULE-01-INCONCLUSIVE",
        rule_name="Inconclusive on Missing or Failed Critical Evidence",
        description="Assigns Inconclusive if baseline checks failed and no authoritative indicators were found.",
        matched=rule_01_matched,
        applied_classification=RiskClassification.INCONCLUSIVE if rule_01_matched else None,
    ))

    if rule_01_matched:
        return (
            RiskClassification.INCONCLUSIVE,
            None,
            round(coverage_ratio, 2),
            triggered_rules,
            contributing_factors,
            f"Risk assessment is Inconclusive: {rule_01_reason}",
            "Inconclusive: Insufficient evidence available to evaluate threat level."
        )

    # -------------------------------------------------------------------------
    # RULE-02: Confirmed Malicious on Authoritative Threat Intelligence or Exploit
    # -------------------------------------------------------------------------
    rule_02_matched = False
    if has_authoritative_threat:
        # Verify strictly non-AI origin
        auth_items = [
            ind for ind in classified.classified_indicators
            if ind.is_authoritative_threat and ind.category != EvidenceCategory.AI_ANALYSIS
        ]
        if auth_items:
            rule_02_matched = True

    triggered_rules.append(TriggeredRule(
        rule_id="RULE-02-CONFIRMED-MALICIOUS",
        rule_name="Confirmed Malicious on Authoritative Evidence",
        description="Requires verified threat intelligence feed match, SSRF block, or cryptographic compromise.",
        matched=rule_02_matched,
        applied_classification=RiskClassification.CONFIRMED_MALICIOUS if rule_02_matched else None,
    ))

    if rule_02_matched:
        final_score = max(90, min(100, raw_score_int))
        auth_titles = ", ".join(f"'{i.title}'" for i in auth_items)
        return (
            RiskClassification.CONFIRMED_MALICIOUS,
            final_score,
            round(max(0.85, coverage_ratio), 2),
            triggered_rules,
            contributing_factors,
            f"Target is confirmed malicious based on authoritative evidence: {auth_titles}.",
            "Confirmed Malicious: Verified security intelligence or active exploit indicators observed."
        )

    # -------------------------------------------------------------------------
    # RULE-03: High Risk on Multiple Significant Indicators or Corroborated Threat
    # -------------------------------------------------------------------------
    rule_03_matched = False
    high_count = classified.high_severity_count
    med_count = classified.medium_severity_count

    # Significant threshold: 2+ High, or 1 High + 2+ Medium, or raw_score >= 65
    if high_count >= 2:
        rule_03_matched = True
    elif high_count >= 1 and med_count >= 2:
        rule_03_matched = True
    elif raw_score_int >= 65:
        rule_03_matched = True
    elif high_count >= 1 and any(i.authority == EvidenceAuthority.CORROBORATED for i in classified.classified_indicators):
        rule_03_matched = True

    triggered_rules.append(TriggeredRule(
        rule_id="RULE-03-HIGH-RISK",
        rule_name="High Risk on Multiple Suspicious or Corroborated Indicators",
        description="Fires when multiple high-severity heuristics or significant threat patterns are present.",
        matched=rule_03_matched,
        applied_classification=RiskClassification.HIGH_RISK if rule_03_matched else None,
    ))

    if rule_03_matched:
        # Cap score at 75 if all indicators are purely heuristic or AI-generated
        all_heuristic = all(i.is_heuristic_only for i in classified.classified_indicators)
        if all_heuristic:
            final_score = min(75, max(65, raw_score_int))
        else:
            final_score = min(89, max(65, raw_score_int))

        return (
            RiskClassification.HIGH_RISK,
            final_score,
            round(coverage_ratio, 2),
            triggered_rules,
            contributing_factors,
            f"High threat probability detected with {high_count} high-severity and {med_count} medium-severity indicator(s).",
            "High Risk: Multiple suspicious indicators strongly suggest a deceptive or hostile website."
        )

    # -------------------------------------------------------------------------
    # RULE-04: Suspicious on Moderate or Single Significant Indicator
    # -------------------------------------------------------------------------
    rule_04_matched = False
    if high_count >= 1:
        rule_04_matched = True
    elif med_count >= 1:
        rule_04_matched = True
    elif raw_score_int >= 25:
        rule_04_matched = True

    triggered_rules.append(TriggeredRule(
        rule_id="RULE-04-SUSPICIOUS",
        rule_name="Suspicious on Anomaly or Moderate Severity Findings",
        description="Fires when one significant heuristic or multiple moderate security weaknesses exist.",
        matched=rule_04_matched,
        applied_classification=RiskClassification.SUSPICIOUS if rule_04_matched else None,
    ))

    if rule_04_matched:
        final_score = min(64, max(25, raw_score_int))
        return (
            RiskClassification.SUSPICIOUS,
            final_score,
            round(coverage_ratio, 2),
            triggered_rules,
            contributing_factors,
            f"Suspicious activity observed: {high_count} high-severity and {med_count} medium-severity indicator(s) require caution.",
            "Suspicious: One or more indicators require user caution and further verification."
        )

    # -------------------------------------------------------------------------
    # RULE-05: Low Risk on Benign / Clean Evidence
    # -------------------------------------------------------------------------
    triggered_rules.append(TriggeredRule(
        rule_id="RULE-05-LOW-RISK",
        rule_name="Low Risk on Absence of Significant Indicators",
        description="Fires when no high or medium severity indicators are found across completed checks.",
        matched=True,
        applied_classification=RiskClassification.LOW_RISK,
    ))

    final_score = min(24, max(0, raw_score_int))
    return (
        RiskClassification.LOW_RISK,
        final_score,
        round(coverage_ratio, 2),
        triggered_rules,
        contributing_factors,
        (
            "No significant malicious indicators were observed within the checks performed. "
            "Note: This result does not guarantee that the destination is permanently benign."
        ),
        "Low Risk: Standard technical checks completed without detecting malicious or suspicious signals."
    )

