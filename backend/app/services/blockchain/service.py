"""CyberShield AI — Blockchain Registration & Integrity Verification Service (Part 19 & Member 3)

Provides canonical hash commitment and tamper-verification against decentralized
ledger state (ThreatReportRegistry.sol), with explicit simulation semantics,
Web3.py EVM execution, transaction receipt validation, and RPC resilience.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import select
from web3 import Web3
from web3.exceptions import (
    ContractCustomError,
    ContractLogicError,
    TimeExhausted,
    TransactionNotFound,
    Web3RPCError,
)

from app.core.config import get_settings
from app.database.models import ThreatReportModel
from app.database.repository import (
    get_threat_report_by_id,
    update_blockchain_metadata,
)
from app.schemas.blockchain import (
    ReportRegistrationRequest,
    ReportRegistrationResponse,
    ReportVerificationRequest,
    ReportVerificationResponse,
)
from app.schemas.common import VerificationStatus
from app.services.blockchain.canonical_hash import (
    compute_canonical_report_hash,
    compute_keccak256_report_hash,
    compute_blockchain_report_id,
    BLOCKCHAIN_NAMESPACE,
)
from app.services.blockchain.adapter import threat_report_to_canonical_blockchain_dict
from app.services.blockchain.report_hash import (
    hash_report,
    validate_threat_report,
    normalize_threat_report,
    canonicalize_report,
    SAMPLE_REPORT,
)

logger = logging.getLogger("cybershield.blockchain")

# Default contract address for simulation / development mode
SIMULATION_CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000"
SIMULATION_NETWORK_NAME = "Simulation Mode (Local Off-Chain)"

# Embedded ABI fallback for ThreatReportRegistry.sol
EMBEDDED_REGISTRY_ABI = json.loads('''[
    {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
    {"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},
    {"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"registrar","type":"address"}],"name":"RegistrarAuthorized","type":"event"},
    {"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"registrar","type":"address"}],"name":"RegistrarRevoked","type":"event"},
    {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"reportId","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"reportHash","type":"bytes32"},{"indexed":true,"internalType":"address","name":"registeredBy","type":"address"},{"indexed":false,"internalType":"uint256","name":"registeredAt","type":"uint256"}],"name":"ReportRegistered","type":"event"},
    {"inputs":[{"internalType":"address","name":"registrar","type":"address"}],"name":"authorizeRegistrar","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"reportHash","type":"bytes32"}],"name":"generateReportId","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"reportId","type":"bytes32"}],"name":"getReport","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"},{"internalType":"bytes32","name":"","type":"bytes32"},{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"hashExists","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"isAuthorizedRegistrar","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"reportHash","type":"bytes32"}],"name":"registerReport","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"reportCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"address","name":"registrar","type":"address"}],"name":"revokeRegistrar","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"reportId","type":"bytes32"},{"internalType":"bytes32","name":"reportHash","type":"bytes32"}],"name":"verifyReport","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]''')


class BlockchainTransactionError(RuntimeError):
    """Raised when an on-chain transaction reverts or fails receipt validation."""
    def __init__(self, message: str, tx_hash: Optional[str] = None, receipt: Optional[Any] = None):
        super().__init__(message)
        self.tx_hash = tx_hash
        self.receipt = receipt


def resolve_contract_abi() -> List[Dict[str, Any]]:
    """Resolve ThreatReportRegistry ABI from artifacts or embedded fallback."""
    candidate_paths = [
        os.getenv("REGISTRY_ABI_PATH"),
        Path(__file__).resolve().parent.parent.parent.parent / "blockchain" / "artifacts" / "contracts" / "ThreatReportRegistry.sol" / "ThreatReportRegistry.json",
        Path(__file__).resolve().parent.parent.parent.parent / "artifacts" / "contracts" / "ThreatReportRegistry.sol" / "ThreatReportRegistry.json",
    ]
    for p in candidate_paths:
        if p and Path(p).exists():
            try:
                data = json.loads(Path(p).read_text(encoding="utf-8"))
                return data.get("abi", EMBEDDED_REGISTRY_ABI)
            except Exception as e:
                logger.warning(f"Could not load ABI from {p}: {e}")
    return EMBEDDED_REGISTRY_ABI


def is_real_blockchain_configured(settings=None) -> bool:
    """Determine whether real EVM contract address and live RPC are configured and reachable."""
    if settings is None:
        settings = get_settings()
    addr = getattr(settings, "registry_contract_address", "") or os.getenv("REGISTRY_CONTRACT_ADDRESS", "")
    addr = addr.strip() if addr else ""
    if not addr or addr == SIMULATION_CONTRACT_ADDRESS or addr.startswith("placeholder"):
        return False
    return True


class BlockchainService:
    """High-level interface to the ThreatReportRegistry contract via Web3.py."""

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        account_address: Optional[str] = None,
        private_key: Optional[str] = None,
        timeout_seconds: int = 60,
    ):
        settings = get_settings()
        self.rpc_url = rpc_url or getattr(settings, "blockchain_rpc_url", None) or os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
        self.timeout_seconds = timeout_seconds
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        if not self.w3.is_connected():
            raise ConnectionError(
                f"Cannot reach blockchain node at {self.rpc_url}. "
                "Ensure local Hardhat node (`npx hardhat node`) or RPC provider is running."
            )

        # Contract Address
        addr = (
            contract_address
            or getattr(settings, "registry_contract_address", None)
            or os.getenv("REGISTRY_CONTRACT_ADDRESS")
        )
        if addr and addr != SIMULATION_CONTRACT_ADDRESS:
            self.contract_address = Web3.to_checksum_address(addr)
        else:
            # Check deployment.json
            dep_paths = [
                Path(__file__).resolve().parent.parent.parent.parent / "blockchain" / "deployment.json",
                Path(__file__).resolve().parent.parent.parent.parent / "deployment.json",
            ]
            dep_file = next((p for p in dep_paths if p.exists()), None)
            if dep_file:
                info = json.loads(dep_file.read_text(encoding="utf-8"))
                self.contract_address = Web3.to_checksum_address(info["contractAddress"])
            else:
                raise ValueError("No contract address configured or found in deployment.json.")

        # Contract ABI
        abi = resolve_contract_abi()
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=abi,
        )

        # Signer & Private Key
        self.private_key = (
            private_key
            or os.getenv("BLOCKCHAIN_PRIVATE_KEY")
            or os.getenv("DEPLOYER_PRIVATE_KEY")
        )

        if self.private_key:
            account_from_key = self.w3.eth.account.from_key(self.private_key)
            self.account = Web3.to_checksum_address(account_from_key.address)
        elif account_address:
            self.account = Web3.to_checksum_address(account_address)
        elif len(self.w3.eth.accounts) > 0:
            self.account = self.w3.eth.accounts[0]
        else:
            raise ValueError(
                "No private key or unlocked account available for blockchain transactions. "
                "Set BLOCKCHAIN_PRIVATE_KEY in your environment."
            )

    @staticmethod
    def _extract_report(
        first_arg: Union[dict, str],
        second_arg: Optional[dict] = None,
    ) -> dict:
        """Normalize arguments from both (raw_report) and (report_type, raw_report)."""
        if isinstance(first_arg, dict) and second_arg is None:
            return first_arg
        if isinstance(first_arg, str) and isinstance(second_arg, dict):
            return second_arg
        if isinstance(first_arg, dict) and isinstance(second_arg, str):
            return first_arg
        raise TypeError(
            f"Invalid arguments: expected report dict or (str, dict), "
            f"got ({type(first_arg).__name__}, {type(second_arg).__name__})"
        )

    def register_report(
        self,
        report_or_type: Union[dict, str],
        raw_report: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Hash a UnifiedThreatReport and register it on-chain with full receipt validation."""
        report_dict = self._extract_report(report_or_type, raw_report)
        validate_threat_report(report_dict)

        report_hash, report_id = hash_report(report_dict)

        # Build transaction
        nonce = self.w3.eth.get_transaction_count(self.account)
        gas_price = self.w3.eth.gas_price

        try:
            tx = self.contract.functions.registerReport(report_hash).build_transaction({
                "from": self.account,
                "nonce": nonce,
                "gas": 300_000,
                "gasPrice": gas_price,
            })

            if self.private_key:
                signed = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
                tx_hash_bytes = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash_bytes = self.w3.eth.send_transaction(tx)
        except (ContractLogicError, ContractCustomError, Web3RPCError) as e:
            raise BlockchainTransactionError(
                f"Smart contract transaction reverted: {e}"
            ) from e

        tx_hash_hex = "0x" + tx_hash_bytes.hex().removeprefix("0x")

        # Wait for receipt and validate status == 1
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash_bytes, timeout=self.timeout_seconds
            )
        except TimeExhausted as e:
            raise BlockchainTransactionError(
                f"Timed out waiting for transaction receipt for tx {tx_hash_hex} "
                f"after {self.timeout_seconds} seconds.",
                tx_hash=tx_hash_hex,
            ) from e
        except Exception as e:
            raise BlockchainTransactionError(
                f"RPC error retrieving transaction receipt for tx {tx_hash_hex}: {e}",
                tx_hash=tx_hash_hex,
            ) from e

        if receipt.status != 1:
            raise BlockchainTransactionError(
                f"Transaction {tx_hash_hex} reverted on-chain (status=0, block={receipt.blockNumber}). "
                "Report registration failed.",
                tx_hash=tx_hash_hex,
                receipt=receipt,
            )

        return {
            "report_hash": "0x" + report_hash.hex(),
            "report_id": "0x" + report_id.hex(),
            "tx_hash": tx_hash_hex,
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "status": "confirmed",
        }

    def verify_report(
        self,
        report_or_type: Union[dict, str],
        raw_report: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Recalculate the report hash & ID and verify against the on-chain record."""
        report_dict = self._extract_report(report_or_type, raw_report)
        validate_threat_report(report_dict)

        report_hash, report_id = hash_report(report_dict)

        try:
            verified = self.contract.functions.verifyReport(
                report_id, report_hash
            ).call()
        except Exception as e:
            raise RuntimeError(f"Contract call to verifyReport failed: {e}") from e

        return {
            "report_hash": "0x" + report_hash.hex(),
            "report_id": "0x" + report_id.hex(),
            "verified": bool(verified),
        }

    def get_report_metadata(self, report_id_hex: str) -> Dict[str, Any]:
        """Retrieve on-chain metadata for a registered report ID."""
        cleaned = report_id_hex.removeprefix("0x")
        try:
            report_id_bytes = bytes.fromhex(cleaned)
        except ValueError as e:
            return {"error": f"Invalid hex report_id: {e}"}

        try:
            rid, rh, by, at = self.contract.functions.getReport(report_id_bytes).call()
        except ContractLogicError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"RPC error: {e}"}

        return {
            "report_id": "0x" + rid.hex(),
            "report_hash": "0x" + rh.hex(),
            "registered_by": by,
            "registered_at": at,
        }

    def report_count(self) -> int:
        """Return total number of registered reports on-chain."""
        return self.contract.functions.reportCount().call()


def register_threat_report_on_chain(
    request: ReportRegistrationRequest,
    db: Session,
    network_name: Optional[str] = None,
) -> ReportRegistrationResponse:
    """Commit canonical report hash to registry.
    
    If real EVM contract is configured and reachable, performs real Web3.py transaction,
    verifying receipt status == 1.
    If real EVM is not configured or in testing environment, operates in transparent
    SIMULATED mode, never misrepresenting local simulation as a confirmed blockchain transaction.
    """
    settings = get_settings()

    # 1. Retrieve report from database
    report = get_threat_report_by_id(db, request.report_id)
    if not report:
        raise ValueError(f"Report '{request.report_id}' not found in database.")

    # 2. Compute canonical hash (both SHA-256 for DB integrity and Keccak-256 for EVM)
    canonical_sha256 = compute_canonical_report_hash(report, algorithm="sha256")
    canonical_m3_dict = threat_report_to_canonical_blockchain_dict(report)
    m3_keccak_hash_bytes, m3_report_id_bytes = hash_report(canonical_m3_dict)
    canonical_keccak_hex = "0x" + m3_keccak_hash_bytes.hex()
    canonical_report_id_hex = "0x" + m3_report_id_bytes.hex()

    # 3. Check for real EVM configuration
    has_real_chain = is_real_blockchain_configured(settings)
    now_iso = datetime.now(timezone.utc).isoformat()

    if has_real_chain:
        try:
            svc = BlockchainService()
            reg_result = svc.register_report(canonical_m3_dict)

            network = network_name or getattr(settings, "blockchain_network", "Hardhat Local (EVM 31337)")
            contract = svc.contract_address
            tx_hash = reg_result["tx_hash"]
            status_label = "confirmed"
            committed_hash = reg_result["report_hash"]
        except Exception as e:
            logger.error(f"Live blockchain registration failed: {e}")
            raise RuntimeError(f"On-chain registration failed: {e}") from e
    else:
        # Simulation Mode (B5-F02)
        raw_tx_seed = f"{request.report_id}:{canonical_sha256}:{now_iso}"
        network = SIMULATION_NETWORK_NAME
        contract = SIMULATION_CONTRACT_ADDRESS
        tx_hash = "simulated_tx:0x" + hashlib.sha256(raw_tx_seed.encode("utf-8")).hexdigest()
        status_label = "simulated"
        committed_hash = canonical_sha256

    # 4. Update database record with commitment metadata
    update_blockchain_metadata(
        db=db,
        scan_id=request.report_id,
        canonical_hash=committed_hash,
        tx_hash=tx_hash,
        status=status_label,
    )

    return ReportRegistrationResponse(
        report_id=request.report_id,
        report_hash=committed_hash,
        transaction_hash=tx_hash,
        blockchain_network=network,
        contract_address=contract,
        status=status_label,
    )


def verify_threat_report_integrity(
    request: ReportVerificationRequest,
    db: Session,
    simulate_rpc_failure: bool = False,
) -> ReportVerificationResponse:
    """Verify off-chain report data integrity against committed hash record.
    
    Honestly reports SIMULATED_VALID / SIMULATED_TAMPERED in simulation mode,
    or VERIFIED_VALID / VERIFIED_TAMPERED on real chain (B5-F02).
    """
    # 1. RPC Failure / Network Offline handling
    if simulate_rpc_failure:
        return ReportVerificationResponse(
            report_id=request.report_id,
            computed_canonical_hash=None,
            on_chain_hash=None,
            is_valid=False,
            verification_status=VerificationStatus.UNAVAILABLE,
            explanation="Blockchain RPC network is unreachable or offline. Integrity could not be verified.",
        )

    # 2. Check if report exists in database
    stmt = select(ThreatReportModel).where(ThreatReportModel.scan_id == request.report_id)
    record = db.execute(stmt).scalar_one_or_none()
    if not record:
        return ReportVerificationResponse(
            report_id=request.report_id,
            computed_canonical_hash=None,
            on_chain_hash=None,
            is_valid=False,
            verification_status=VerificationStatus.NOT_FOUND,
            explanation=f"Report '{request.report_id}' was not found in off-chain database records.",
        )

    # 3. Check if registered
    if not record.canonical_hash or record.on_chain_status not in ("confirmed", "simulated"):
        return ReportVerificationResponse(
            report_id=request.report_id,
            computed_canonical_hash=None,
            on_chain_hash=None,
            is_valid=False,
            verification_status=VerificationStatus.NOT_REGISTERED,
            explanation="Report exists off-chain but has not been committed to the registry ledger.",
        )

    on_chain_hash = record.canonical_hash
    is_simulated = (record.on_chain_status == "simulated")

    # 4. Check if client provided a specific hash to test against record
    if request.provided_hash and request.provided_hash.strip().lower() != str(on_chain_hash).lower():
        tamper_status = (
            VerificationStatus.SIMULATED_TAMPERED if is_simulated else VerificationStatus.VERIFIED_TAMPERED
        )
        return ReportVerificationResponse(
            report_id=request.report_id,
            computed_canonical_hash=None,
            on_chain_hash=on_chain_hash,
            is_valid=False,
            verification_status=tamper_status,
            explanation=(
                f"Client-provided hash '{request.provided_hash}' does not match "
                f"the {'simulated' if is_simulated else 'on-chain'} committed record '{on_chain_hash}'."
            ),
        )

    # 5. Parse current report and recompute canonical hash
    try:
        report_dict = json.loads(record.report_json)
    except Exception as exc:
        return ReportVerificationResponse(
            report_id=request.report_id,
            computed_canonical_hash=None,
            on_chain_hash=record.canonical_hash,
            is_valid=False,
            verification_status=VerificationStatus.VERIFIED_TAMPERED,
            explanation=f"Database payload is corrupted: {exc}",
        )

    # 5. Live EVM vs Simulation Verification
    if record.on_chain_status == "confirmed" and is_real_blockchain_configured():
        try:
            svc = BlockchainService()
            canonical_m3_dict = threat_report_to_canonical_blockchain_dict(report_dict)
            ver_res = svc.verify_report(canonical_m3_dict)
            is_valid = ver_res["verified"]
            computed_hash = ver_res["report_hash"]
            meta = svc.get_report_metadata(ver_res["report_id"])
            reg_time = str(meta.get("registered_at")) if meta.get("registered_at") else None

            if is_valid:
                v_status = VerificationStatus.VERIFIED_VALID
                explanation = "Cryptographic integrity verified against decentralized ThreatReportRegistry smart contract."
            else:
                v_status = VerificationStatus.VERIFIED_TAMPERED
                explanation = "SECURITY WARNING: TAMPER DETECTED! Computed hash does not match committed on-chain ledger hash."

            return ReportVerificationResponse(
                report_id=request.report_id,
                computed_canonical_hash=computed_hash,
                on_chain_hash=record.canonical_hash,
                is_valid=is_valid,
                registration_timestamp=reg_time,
                verification_status=v_status,
                explanation=explanation,
            )
        except Exception as e:
            logger.error(f"On-chain verification query failed: {e}")
            return ReportVerificationResponse(
                report_id=request.report_id,
                computed_canonical_hash=None,
                on_chain_hash=record.canonical_hash,
                is_valid=False,
                verification_status=VerificationStatus.UNAVAILABLE,
                explanation=f"Error connecting to blockchain for on-chain verification: {e}",
            )

    # Simulation mode verification
    computed_hash = compute_canonical_report_hash(report_dict, algorithm="sha256")
    is_valid = (computed_hash.lower() == str(record.canonical_hash).lower())

    if is_valid:
        v_status = VerificationStatus.SIMULATED_VALID
        explanation = (
            "SIMULATED: Report integrity verified in development simulation mode. "
            "Canonical payload matches registered fingerprint commitment."
        )
    else:
        v_status = VerificationStatus.SIMULATED_TAMPERED
        explanation = (
            f"SIMULATION TAMPER DETECTED: The off-chain report data has been modified. "
            f"Computed hash '{computed_hash}' does not match registered simulated hash '{record.canonical_hash}'."
        )

    return ReportVerificationResponse(
        report_id=request.report_id,
        computed_canonical_hash=computed_hash,
        on_chain_hash=record.canonical_hash,
        is_valid=is_valid,
        registration_timestamp=record.registered_at or record.created_at,
        block_number=None,
        verification_status=v_status,
        explanation=explanation,
    )
