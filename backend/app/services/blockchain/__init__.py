"""CyberShield AI — Blockchain & Decentralized Report Integrity Module."""

from app.services.blockchain.canonical_hash import (
    compute_canonical_report_hash,
    compute_keccak256_report_hash,
    compute_blockchain_report_id,
    extract_canonical_payload,
)
from app.services.blockchain.service import (
    BlockchainService,
    BlockchainTransactionError,
    register_threat_report_on_chain,
    verify_threat_report_integrity,
    is_real_blockchain_configured,
)
from app.services.blockchain.adapter import threat_report_to_canonical_blockchain_dict

__all__ = [
    "compute_canonical_report_hash",
    "compute_keccak256_report_hash",
    "compute_blockchain_report_id",
    "extract_canonical_payload",
    "BlockchainService",
    "BlockchainTransactionError",
    "register_threat_report_on_chain",
    "verify_threat_report_integrity",
    "is_real_blockchain_configured",
    "threat_report_to_canonical_blockchain_dict",
]
