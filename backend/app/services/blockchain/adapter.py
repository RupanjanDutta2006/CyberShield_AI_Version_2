"""CyberShield AI — Blockchain Threat Report Adapter

Bridges Member 1's comprehensive UnifiedThreatReport Pydantic models with
Member 3's 10-field canonical blockchain schema for cryptographic hashing
and on-chain registry commitment.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
import re

from app.schemas.threat_report import UnifiedThreatReport
from app.schemas.common import RiskClassification, ScanType, AnalysisStatus
from app.services.blockchain.report_hash import normalize_number, VALID_CATEGORIES, VALID_SEVERITIES, VALID_STATUSES


def map_risk_classification_to_severity(classification: Union[RiskClassification, str]) -> str:
    """Map Member 1 RiskClassification enum to Member 3 severity string."""
    val = classification.value if isinstance(classification, RiskClassification) else str(classification)
    val_upper = val.upper().replace(" ", "_")

    if val_upper in ("CONFIRMED_MALICIOUS", "CRITICAL"):
        return "critical"
    if val_upper in ("HIGH_RISK", "HIGH"):
        return "high"
    if val_upper in ("SUSPICIOUS", "MEDIUM"):
        return "medium"
    if val_upper in ("LOW_RISK", "LOW"):
        return "low"
    return "informational"


def determine_category_from_report(report: Union[UnifiedThreatReport, Dict[str, Any]]) -> str:
    """Determine threat category from report input and findings."""
    if isinstance(report, UnifiedThreatReport):
        scan_type = report.submitted_input.type
        findings = report.technical_findings
        ai = report.ai_analysis
    else:
        scan_type = report.get("submitted_input", {}).get("type", "")
        findings = report.get("technical_findings", [])
        ai = report.get("ai_analysis")

    # If analyzed message, categorize as social engineering or scam
    if scan_type in (ScanType.MESSAGE, "message") or ai:
        return "social_engineering"

    # Inspect findings for phishing or malware
    text_corpus = " ".join([
        str(f.title if hasattr(f, "title") else f.get("title", "")) + " " +
        str(f.description if hasattr(f, "description") else f.get("description", ""))
        for f in findings
    ]).lower()

    if "malware" in text_corpus or "payload" in text_corpus or "trojan" in text_corpus:
        return "malware"
    if "phishing" in text_corpus or "credential" in text_corpus or "spoof" in text_corpus:
        return "phishing"

    return "phishing"


def extract_indicators(report: Union[UnifiedThreatReport, Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extract observable indicators of compromise (IOCs) from report."""
    indicators: List[Dict[str, str]] = []

    if isinstance(report, UnifiedThreatReport):
        target = report.submitted_input.value
        scan_type = report.submitted_input.type
        findings = report.technical_findings
        threat_intel = report.threat_intelligence
    else:
        target = report.get("submitted_input", {}).get("value", "")
        scan_type = report.get("submitted_input", {}).get("type", "")
        findings = report.get("technical_findings", [])
        threat_intel = report.get("threat_intelligence", [])

    # Target indicator
    if target:
        ioc_type = "url" if scan_type in (ScanType.URL, "url") else "domain"
        indicators.append({"ioc_type": ioc_type, "value": str(target).strip()})

    # Extract indicators from findings
    for f in findings:
        observed = f.observed_value if hasattr(f, "observed_value") else f.get("observed_value")
        f_type = f.finding_type if hasattr(f, "finding_type") else f.get("finding_type", "")
        if observed and isinstance(observed, str):
            if "ip" in str(f_type).lower():
                indicators.append({"ioc_type": "ip", "value": observed.strip()})
            elif "hash" in str(f_type).lower():
                indicators.append({"ioc_type": "hash", "value": observed.strip()})
            elif "domain" in str(f_type).lower():
                indicators.append({"ioc_type": "domain", "value": observed.strip()})

    # Deduplicate indicators by (ioc_type, value)
    seen = set()
    unique_iocs = []
    for item in indicators:
        key = (item["ioc_type"], item["value"])
        if key not in seen and item["value"]:
            seen.add(key)
            unique_iocs.append(item)

    unique_iocs.sort(key=lambda x: (x["ioc_type"], x["value"]))
    return unique_iocs


def threat_report_to_canonical_blockchain_dict(
    report: Union[UnifiedThreatReport, Dict[str, Any]]
) -> Dict[str, Any]:
    """Convert Member 1 UnifiedThreatReport into Member 3 canonical 10-field dictionary.
    
    Ensures full compatibility with Member 3's validate_threat_report()
    and normalize_threat_report() functions.
    """
    if isinstance(report, UnifiedThreatReport):
        data = report.model_dump(mode="json")
    else:
        data = dict(report)

    # 1. report_id
    report_id = str(data.get("scan_id") or data.get("report_id") or "").strip()
    if not report_id:
        report_id = "CSR-AUTO-GEN"

    # 2. schema_version
    schema_version = "1.0"

    # 3. detected_at
    detected_at = (
        data.get("submitted_input", {}).get("normalized_at")
        or data.get("detected_at")
        or data.get("timestamp")
        or datetime.now(timezone.utc).isoformat()
    )
    if not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", detected_at):
        detected_at = f"{detected_at}Z"

    # 4. generated_at
    generated_at = (
        data.get("timestamp")
        or data.get("generated_at")
        or datetime.now(timezone.utc).isoformat()
    )
    if not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", generated_at):
        generated_at = f"{generated_at}Z"

    # 5. severity
    risk_info = data.get("risk", {})
    raw_classification = risk_info.get("classification") or data.get("severity") or "INCONCLUSIVE"
    severity = map_risk_classification_to_severity(raw_classification)

    # 6. category
    raw_category = data.get("category")
    if raw_category and str(raw_category).lower() in VALID_CATEGORIES:
        category = str(raw_category).lower()
    else:
        category = determine_category_from_report(data)

    # 7. status
    raw_status = data.get("status", "COMPLETED")
    status_str = str(raw_status).lower()
    if status_str in ("completed", "analysisstatus.completed"):
        status = "completed"
    elif status_str in ("failed", "analysisstatus.failed", "partial", "analysisstatus.partial"):
        status = "investigating"
    elif status_str in VALID_STATUSES:
        status = status_str
    else:
        status = "completed"

    # 8. confidence_score
    score_val = risk_info.get("score")
    if score_val is not None and not isinstance(score_val, bool):
        confidence_score = normalize_number(score_val, "confidence_score", 0.0, 100.0)
    else:
        conf_ratio = risk_info.get("confidence") or data.get("confidence_score") or 0.0
        if isinstance(conf_ratio, float) and 0.0 <= conf_ratio <= 1.0:
            confidence_score = normalize_number(round(conf_ratio * 100, 1), "confidence_score", 0.0, 100.0)
        else:
            confidence_score = normalize_number(conf_ratio, "confidence_score", 0.0, 100.0)

    # 9. summary
    summary = str(risk_info.get("summary") or data.get("summary") or "Automated cyber threat investigation completed.").strip()

    # 10. description
    target_val = data.get("submitted_input", {}).get("value") or data.get("target") or "target"
    description = str(data.get("description") or f"CyberShield AI comprehensive security audit for {target_val}. Classification: {severity.upper()}.").strip()

    # Optional / nested fields
    indicators = extract_indicators(data)
    affected_assets = [
        {"asset_type": "target", "identifier": str(target_val).strip()}
    ] if target_val else []

    remediation_steps = [
        {"action": str(rec).strip(), "priority": idx + 1}
        for idx, rec in enumerate(data.get("recommendations", []))
        if str(rec).strip()
    ]
    if not remediation_steps and data.get("remediation_steps"):
        remediation_steps = data["remediation_steps"]

    mitre_techniques = sorted(list(data.get("mitre_techniques") or []))

    return {
        "report_id": report_id,
        "schema_version": schema_version,
        "detected_at": detected_at,
        "generated_at": generated_at,
        "severity": severity,
        "category": category,
        "status": status,
        "confidence_score": confidence_score,
        "summary": summary,
        "description": description,
        "indicators": indicators,
        "affected_assets": affected_assets,
        "remediation_steps": remediation_steps,
        "mitre_techniques": mitre_techniques,
        "threat_actor": str(data.get("threat_actor") or "unknown").strip(),
    }

