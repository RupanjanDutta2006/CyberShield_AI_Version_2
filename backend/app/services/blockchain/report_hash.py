"""
CyberShield AI — Report Hash Generator v2 (Stabilized)
======================================================
Deterministic canonical serialization and Keccak-256 hashing for
CyberShield AI UnifiedThreatReport records.

This module is the Python equivalent of:
  - lib/blockchain/threatReport.ts  → normalizeThreatReport() & validateThreatReport()
  - app/api/blockchain/route.ts     → computeReportHash() / computeReportId()

All implementations produce IDENTICAL hashes for the same report.

Schema version: 1.0
Namespace:      CYBERSHIELD_REPORT_V1
"""

import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from web3 import Web3

# ─────────────────────────────────────────────────────────────────
#  Namespace — must exactly match:
#    Solidity:   string private constant NAMESPACE = "CYBERSHIELD_REPORT_V1";
#    TypeScript: const NAMESPACE = "CYBERSHIELD_REPORT_V1";
# ─────────────────────────────────────────────────────────────────
NAMESPACE = "CYBERSHIELD_REPORT_V1"

# ─────────────────────────────────────────────────────────────────
#  Allowed Enum Sets for Strict Validation
# ─────────────────────────────────────────────────────────────────
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
VALID_CATEGORIES = {
    "phishing", "malware", "scam", "ddos", "intrusion",
    "ransomware", "data_leak", "vulnerability", "social_engineering",
    "defacement", "other", "unknown"
}
VALID_STATUSES = {
    "detected", "investigating", "confirmed", "mitigated",
    "resolved", "false_positive", "completed", "unknown"
}
VALID_SCHEMA_VERSIONS = {"1.0", "1.0.0"}

ISO_8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


# ─────────────────────────────────────────────────────────────────
#  Numeric Normalization Helper
#  Ensures cross-language consistency with JavaScript:
#    - JavaScript Number(87)   → 87   → serialized as 87
#    - JavaScript Number(87.0) → 87   → serialized as 87
#    - JavaScript Number(87.5) → 87.5 → serialized as 87.5
# ─────────────────────────────────────────────────────────────────

def normalize_number(value: Any, field_name: str = "number", min_val: float = 0.0, max_val: float = 100.0) -> Union[int, float]:
    """
    Validate and normalize a numeric value.
    Rejects booleans, NaN, Infinity, and out-of-range values.
    Normalizes whole floats (e.g. 87.0) to int (87) to match JavaScript JSON serialization.
    Preserves true fractional decimals (e.g. 87.5) as float.
    """
    if isinstance(value, bool):
        raise ValueError(f"Field '{field_name}' must be a number, not boolean.")

    if not isinstance(value, (int, float)):
        # Attempt conversion from string if numeric
        try:
            value = float(value)
        except (TypeError, ValueError) as err:
            raise ValueError(f"Field '{field_name}' must be a valid number: {value}") from err

    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"Field '{field_name}' must not be NaN or Infinity.")

    if not (min_val <= value <= max_val):
        raise ValueError(
            f"Field '{field_name}' value {value} out of range [{min_val}, {max_val}]."
        )

    # If the float has no fractional component, normalize to integer
    if float(value).is_integer():
        return int(value)

    return float(value)


# ─────────────────────────────────────────────────────────────────
#  Validation Logic (Phase 7)
# ─────────────────────────────────────────────────────────────────

def validate_threat_report(raw: Any) -> Dict[str, Any]:
    """
    Strictly validate a raw UnifiedThreatReport dictionary against
    all 10 documented required fields, type bounds, and structure constraints.

    Required Fields:
      1. report_id
      2. schema_version
      3. detected_at
      4. generated_at
      5. severity
      6. category
      7. status
      8. confidence_score
      9. summary
      10. description
    """
    if not isinstance(raw, dict):
        raise TypeError(f"Report must be a dictionary, got {type(raw).__name__}")

    required_fields = [
        "report_id", "schema_version", "detected_at", "generated_at",
        "severity", "category", "status", "confidence_score",
        "summary", "description"
    ]

    missing = [f for f in required_fields if f not in raw or raw[f] is None]
    if missing:
        raise ValueError(f"Missing required report fields: {', '.join(missing)}")

    # 1. report_id
    report_id = str(raw["report_id"]).strip()
    if not report_id:
        raise ValueError("Field 'report_id' cannot be empty.")

    # 2. schema_version
    schema_version = str(raw["schema_version"]).strip()
    if schema_version not in VALID_SCHEMA_VERSIONS:
        raise ValueError(
            f"Invalid schema_version '{schema_version}'. Supported: {sorted(VALID_SCHEMA_VERSIONS)}"
        )

    # 3. detected_at
    detected_at = str(raw["detected_at"]).strip()
    if not ISO_8601_REGEX.match(detected_at):
        raise ValueError(f"Field 'detected_at' is not a valid ISO-8601 timestamp: '{detected_at}'")

    # 4. generated_at
    generated_at = str(raw["generated_at"]).strip()
    if not ISO_8601_REGEX.match(generated_at):
        raise ValueError(f"Field 'generated_at' is not a valid ISO-8601 timestamp: '{generated_at}'")

    # 5. severity
    severity = str(raw["severity"]).strip().lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{raw['severity']}'. Allowed: {sorted(VALID_SEVERITIES)}")

    # 6. category
    category = str(raw["category"]).strip().lower()
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{raw['category']}'. Allowed: {sorted(VALID_CATEGORIES)}")

    # 7. status
    status = str(raw["status"]).strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{raw['status']}'. Allowed: {sorted(VALID_STATUSES)}")

    # 8. confidence_score (0 - 100)
    confidence_score = normalize_number(raw["confidence_score"], "confidence_score", 0.0, 100.0)

    # 9. summary
    summary = str(raw["summary"]).strip()
    if not summary:
        raise ValueError("Field 'summary' cannot be empty.")

    # 10. description
    description = str(raw["description"]).strip()
    if not description:
        raise ValueError("Field 'description' cannot be empty.")

    # Nested structures validation
    indicators = raw.get("indicators")
    if indicators is not None:
        if not isinstance(indicators, list):
            raise TypeError("Field 'indicators' must be a list.")
        for idx, ioc in enumerate(indicators):
            if not isinstance(ioc, dict) or "ioc_type" not in ioc or "value" not in ioc:
                raise ValueError(f"Indicator at index {idx} must be a dict with 'ioc_type' and 'value'.")

    affected_assets = raw.get("affected_assets")
    if affected_assets is not None:
        if not isinstance(affected_assets, list):
            raise TypeError("Field 'affected_assets' must be a list.")
        for idx, asset in enumerate(affected_assets):
            if not isinstance(asset, dict) or "asset_type" not in asset or "identifier" not in asset:
                raise ValueError(f"Affected asset at index {idx} must be a dict with 'asset_type' and 'identifier'.")

    remediation_steps = raw.get("remediation_steps")
    if remediation_steps is not None:
        if not isinstance(remediation_steps, list):
            raise TypeError("Field 'remediation_steps' must be a list.")
        for idx, step in enumerate(remediation_steps):
            if not isinstance(step, dict) or "action" not in step or "priority" not in step:
                raise ValueError(f"Remediation step at index {idx} must be a dict with 'action' and 'priority'.")
            if isinstance(step["priority"], bool) or not isinstance(step["priority"], (int, float)):
                raise ValueError(f"Remediation step priority at index {idx} must be an integer.")

    mitre_techniques = raw.get("mitre_techniques")
    if mitre_techniques is not None:
        if not isinstance(mitre_techniques, list):
            raise TypeError("Field 'mitre_techniques' must be a list.")

    return raw


# ─────────────────────────────────────────────────────────────────
#  Canonical JSON Serialization
#  Rules (matching TypeScript canonicalize()):
#    - Sorted keys at every nesting level
#    - Compact separators (",", ":")
#    - ensure_ascii=False (Unicode preserved)
# ─────────────────────────────────────────────────────────────────

def canonicalize_report(report: dict) -> str:
    """
    Deterministic JSON serialization of a report dict.
    Identical to the TypeScript canonicalize() function.
    """
    return json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


# ─────────────────────────────────────────────────────────────────
#  UnifiedThreatReport Normalizer
# ─────────────────────────────────────────────────────────────────

def normalize_threat_report(raw: dict) -> dict:
    """
    Validate and normalize a raw UnifiedThreatReport dict into the
    canonical form used for hashing.
    """
    # Run validation first
    validated = validate_threat_report(raw)

    # ── indicators ───────────────────────────────────────────────
    indicators = [
        {
            "ioc_type": str(ioc.get("ioc_type", "")).strip(),
            "value":    str(ioc.get("value", "")).strip(),
        }
        for ioc in (validated.get("indicators") or [])
    ]
    indicators.sort(key=lambda x: (x["ioc_type"], x["value"]))

    # ── affected_assets ──────────────────────────────────────────
    affected_assets = [
        {
            "asset_type": str(a.get("asset_type", "")).strip(),
            "identifier": str(a.get("identifier", "")).strip(),
        }
        for a in (validated.get("affected_assets") or [])
    ]
    affected_assets.sort(key=lambda x: (x["asset_type"], x["identifier"]))

    # ── remediation_steps ────────────────────────────────────────
    remediation_steps = [
        {
            "action":   str(s.get("action", "")).strip(),
            "priority": int(s.get("priority", 0)),
        }
        for s in (validated.get("remediation_steps") or [])
    ]
    remediation_steps.sort(key=lambda x: x["priority"])

    # ── mitre_techniques ─────────────────────────────────────────
    mitre_techniques = sorted([
        str(t).strip() for t in (validated.get("mitre_techniques") or [])
    ])

    confidence_score = normalize_number(
        validated["confidence_score"], "confidence_score", 0.0, 100.0
    )

    return {
        "report_id":        str(validated["report_id"]).strip(),
        "schema_version":   "1.0",
        "detected_at":      str(validated["detected_at"]).strip(),
        "generated_at":     str(validated["generated_at"]).strip(),
        "severity":         str(validated["severity"]).strip().lower(),
        "category":         str(validated["category"]).strip().lower(),
        "status":           str(validated["status"]).strip().lower(),
        "confidence_score": confidence_score,
        "summary":          str(validated["summary"]).strip(),
        "description":      str(validated["description"]).strip(),
        "indicators":       indicators,
        "affected_assets":  affected_assets,
        "remediation_steps": remediation_steps,
        "mitre_techniques": mitre_techniques,
        "threat_actor":     str(validated.get("threat_actor") or "unknown").strip(),
    }


# ─────────────────────────────────────────────────────────────────
#  Hash Functions
# ─────────────────────────────────────────────────────────────────

def generate_report_hash(raw: dict) -> bytes:
    """
    H = keccak256( canonicalize( normalize(raw) ) )
    Returns 32 bytes. Identical to TypeScript computeReportHash().
    """
    normalized = normalize_threat_report(raw)
    canonical = canonicalize_report(normalized)
    return Web3.keccak(text=canonical)


def generate_report_id(report_hash: bytes) -> bytes:
    """
    ID = keccak256( NAMESPACE_bytes || report_hash_bytes )
    Mirrors Solidity: keccak256(abi.encodePacked(NAMESPACE, reportHash))
    and TypeScript computeReportId().
    """
    namespace_bytes = NAMESPACE.encode("utf-8")   # 21 bytes
    packed = namespace_bytes + bytes(report_hash) # 53 bytes
    return Web3.keccak(primitive=packed)


def hash_report(
    raw_or_type: Union[dict, str],
    raw_optional: Optional[dict] = None,
) -> Tuple[bytes, bytes]:
    """
    Flexible hashing entrypoint supporting both:
      1. hash_report(raw_report: dict)
      2. hash_report(report_type: str, raw_report: dict)

    Returns:
        (report_hash: bytes32, report_id: bytes32)
    """
    if isinstance(raw_or_type, dict) and raw_optional is None:
        data = raw_or_type
    elif isinstance(raw_or_type, str) and isinstance(raw_optional, dict):
        data = raw_optional
    elif isinstance(raw_or_type, dict) and isinstance(raw_optional, str):
        data = raw_or_type
    else:
        raise TypeError(
            f"Invalid arguments to hash_report(): expected dict or (str, dict), "
            f"got ({type(raw_or_type).__name__}, {type(raw_optional).__name__})"
        )

    report_hash = generate_report_hash(data)
    report_id = generate_report_id(report_hash)
    return report_hash, report_id


# ─────────────────────────────────────────────────────────────────
#  Realistic CyberShield AI UnifiedThreatReport Sample
# ─────────────────────────────────────────────────────────────────

SAMPLE_REPORT = {
    "report_id":        "CSR-20261107-00001",
    "schema_version":   "1.0",
    "detected_at":      "2026-11-07T10:00:00.000Z",
    "generated_at":     "2026-11-07T10:05:00.000Z",
    "severity":         "high",
    "category":         "phishing",
    "status":           "detected",
    "confidence_score": 87,
    "summary":          "Credential harvesting phishing campaign targeting corporate email.",
    "description":      "AI detected a phishing campaign using spoofed login pages to harvest credentials. "
                        "Multiple users received emails with malicious links.",
    "indicators": [
        {"ioc_type": "domain", "value": "secure-login-verify.example.com"},
        {"ioc_type": "hash",   "value": "d41d8cd98f00b204e9800998ecf8427e"},
    ],
    "affected_assets": [
        {"asset_type": "service", "identifier": "corporate-email"},
        {"asset_type": "user",    "identifier": "user-group-finance"},
    ],
    "remediation_steps": [
        {"priority": 1, "action": "Block domain secure-login-verify.example.com at DNS level"},
        {"priority": 2, "action": "Force password reset for all users who clicked the link"},
        {"priority": 3, "action": "Enable MFA for all corporate email accounts"},
    ],
    "mitre_techniques": ["T1566", "T1078"],
    "threat_actor":     "unknown",
}


if __name__ == "__main__":
    rh, rid = hash_report(SAMPLE_REPORT)
    normalized = normalize_threat_report(SAMPLE_REPORT)
    canonical = canonicalize_report(normalized)

    print("=" * 70)
    print("  CyberShield AI — Hash Consistency Test")
    print("=" * 70)
    print(f"\n  Report ID     : {SAMPLE_REPORT['report_id']}")
    print(f"  Schema version: {SAMPLE_REPORT['schema_version']}")
    print(f"\n  Canonical JSON (first 120 chars):")
    print(f"  {canonical[:120]}…")
    print(f"\n  Report Hash   : 0x{rh.hex()}")
    print(f"  Report ID     : 0x{rid.hex()}")
    print("=" * 70)
