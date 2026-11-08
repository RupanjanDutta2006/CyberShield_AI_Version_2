"""CyberShield AI — Canonical Report Hashing (Part 19 & Member 3 Integration)

Generates deterministic, tamper-evident cryptographic hashes of Unified Threat Reports
following RFC 8785 JSON Canonicalization Scheme (JCS) principles.
Supports both SHA-256 (internal database audit) and Keccak-256 (EVM blockchain registry).
"""

import hashlib
import json
from typing import Union, Dict, Any, Optional
from web3 import Web3

from app.schemas.threat_report import UnifiedThreatReport

# Member 3 smart contract namespace
BLOCKCHAIN_NAMESPACE = "CYBERSHIELD_REPORT_V1"


def extract_canonical_payload(report: Union[UnifiedThreatReport, Dict[str, Any]]) -> Dict[str, Any]:
    """Extract report fields that constitute the immutable audit payload.
    
    Excludes mutable and post-hash commitment fields:
    - report_integrity (contains the hash itself and tx status)
    - persistence_metadata (contains retrieval counters and DB ids)
    """
    if isinstance(report, UnifiedThreatReport):
        data = report.model_dump(mode="json")
    else:
        data = json.loads(json.dumps(report))

    # Strip mutable fields
    data.pop("report_integrity", None)
    data.pop("persistence_metadata", None)

    return data


def compute_canonical_report_hash(
    report: Union[UnifiedThreatReport, Dict[str, Any]],
    prefix_0x: bool = True,
    algorithm: str = "sha256",
) -> str:
    """Compute deterministic hash of canonical report payload.
    
    Uses sorted keys and compact separators (",", ":") to produce identical
    cryptographic hashes across platforms, languages, and architectures.
    
    Args:
        report: UnifiedThreatReport model or dictionary representation.
        prefix_0x: Whether to return EVM-compatible "0x"-prefixed hex string.
        algorithm: Hashing algorithm - "sha256" (default, Member 1) or "keccak256" (Member 3).
        
    Returns:
        Hex-encoded hash string (66 characters with 0x prefix, or 64 characters).
    """
    canonical_dict = extract_canonical_payload(report)
    canonical_bytes = json.dumps(
        canonical_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if algorithm.lower() == "keccak256":
        keccak_bytes = Web3.keccak(canonical_bytes)
        digest = keccak_bytes.hex().removeprefix("0x")
    else:
        digest = hashlib.sha256(canonical_bytes).hexdigest()

    return f"0x{digest}" if prefix_0x else digest


def compute_keccak256_report_hash(
    report: Union[UnifiedThreatReport, Dict[str, Any]],
    prefix_0x: bool = True,
) -> str:
    """Convenience helper for Member 3 Keccak-256 canonical report hash."""
    return compute_canonical_report_hash(report, prefix_0x=prefix_0x, algorithm="keccak256")


def compute_blockchain_report_id(
    report_hash: Union[str, bytes],
    namespace: str = BLOCKCHAIN_NAMESPACE,
) -> str:
    """Derive deterministic report ID from report hash and namespace.
    
    Mirrors Solidity contract:
    keccak256(abi.encodePacked(NAMESPACE, reportHash))
    """
    if isinstance(report_hash, str):
        cleaned = report_hash.removeprefix("0x")
        hash_bytes = bytes.fromhex(cleaned)
    else:
        hash_bytes = bytes(report_hash)

    packed = namespace.encode("utf-8") + hash_bytes
    id_bytes = Web3.keccak(primitive=packed)
    return "0x" + id_bytes.hex().removeprefix("0x")
