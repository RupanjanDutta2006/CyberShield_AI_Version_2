"""CyberShield AI — Unified Cryptographic Report Verifier & Blockchain Anchor

Handles report canonicalization, cryptographic SHA-256 / Keccak-256 integrity hashing,
and verification against the decentralized ThreatReportRegistry smart contract ledger.
"""

import hashlib
import json
import logging
from typing import Any, Dict, Optional, Tuple

from app.core.config import settings
from app.services.blockchain.service import (
    BlockchainService,
    is_real_blockchain_configured,
)
from app.services.blockchain.canonical_hash import compute_canonical_report_hash

logger = logging.getLogger("cybershield.verifier")


class ReportVerifier:
    """
    Handles report canonicalization, cryptographic SHA-256 integrity hashing,
    and blockchain ledger anchoring & verification.
    """

    @staticmethod
    def build_canonical_payload(
        scan_id: str,
        target: str,
        risk_level: str,
        risk_score: int,
        summary: str,
        evidence: Any,
        recommendations: Any
    ) -> Dict[str, Any]:
        """
        Builds normalized canonical payload for cryptographic report hashing.
        """
        ev_list = evidence if isinstance(evidence, list) else json.loads(evidence or "[]")
        rec_list = recommendations if isinstance(recommendations, list) else json.loads(recommendations or "[]")
        return {
            "evidence": sorted([str(e) for e in ev_list]),
            "recommendations": sorted([str(r) for r in rec_list]),
            "risk_level": str(risk_level),
            "risk_score": int(risk_score),
            "scan_id": str(scan_id),
            "summary": str(summary).strip(),
            "target": str(target).strip()
        }

    @staticmethod
    def canonicalize(data: Dict[str, Any]) -> str:
        """
        Produces deterministic RFC 8785-compliant JSON canonical string.
        Keys are sorted alphabetically, without indentation or extra whitespace.
        """
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    @classmethod
    def calculate_hash(cls, report_payload: Dict[str, Any]) -> str:
        """
        Calculates SHA-256 hash of canonicalized report dictionary.
        """
        canonical_str = cls.canonicalize(report_payload)
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

    @classmethod
    def verify_report_integrity(
        cls,
        stored_hash: str,
        report_data: Dict[str, Any],
        simulated_tampered_summary: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Verifies whether report data has been modified since issuance.
        If simulated_tampered_summary is provided, simulates unauthorized payload alteration.
        Returns: (is_valid, recalculated_hash, audit_notes)
        """
        data_to_hash = dict(report_data)
        if simulated_tampered_summary:
            data_to_hash["summary"] = simulated_tampered_summary.strip()

        recalculated = cls.calculate_hash(data_to_hash)
        if stored_hash == recalculated and not simulated_tampered_summary:
            notes = "Cryptographic integrity verified. Report payload matches original issuance hash exactly."
            return True, recalculated, notes
        else:
            notes = (
                f"INTEGRITY VIOLATION DETECTED! Computed hash ({recalculated[:16]}...) "
                f"does not match stored cryptographic proof ({stored_hash[:16]}...)."
            )
            return False, recalculated, notes

    @classmethod
    async def anchor_on_blockchain(
        cls,
        report_hash: str,
        canonical_m3_dict: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Anchors canonical report on Member 3's ThreatReportRegistry smart contract.
        Returns: (status, transaction_hash)
        """
        if not is_real_blockchain_configured(settings):
            return "locally_hashed", None

        try:
            svc = BlockchainService()
            if canonical_m3_dict:
                reg_result = svc.register_report(canonical_m3_dict)
                return "blockchain_verified", reg_result["tx_hash"]
            else:
                # If only hash provided, attempt direct contract registration
                hash_bytes32 = bytes.fromhex(report_hash.removeprefix("0x"))
                nonce = svc.w3.eth.get_transaction_count(svc.account)
                gas_price = svc.w3.eth.gas_price
                tx = svc.contract.functions.registerReport(hash_bytes32).build_transaction({
                    "from": svc.account,
                    "nonce": nonce,
                    "gas": 300_000,
                    "gasPrice": gas_price,
                })
                if svc.private_key:
                    signed = svc.w3.eth.account.sign_transaction(tx, private_key=svc.private_key)
                    tx_hash_bytes = svc.w3.eth.send_raw_transaction(signed.raw_transaction)
                else:
                    tx_hash_bytes = svc.w3.eth.send_transaction(tx)
                receipt = svc.w3.eth.wait_for_transaction_receipt(tx_hash_bytes, timeout=10)
                if receipt.status == 1:
                    tx_hex = "0x" + tx_hash_bytes.hex().removeprefix("0x")
                    return "blockchain_verified", tx_hex
                return "locally_hashed", None
        except Exception as e:
            logger.warning(f"Blockchain anchoring attempt skipped or failed: {e}. Report preserved off-chain with SHA-256 proof.")
            return "locally_hashed", None

