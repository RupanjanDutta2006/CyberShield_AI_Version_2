"""CyberShield AI — Blockchain & Report Integrity Schemas

Shared contract for Member 3 (Blockchain & Decentralized Trust Engineer).
"""

from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.common import VerificationStatus


class ReportIntegrityMetadata(BaseModel):
    """Integrity commitment metadata embedded in threat reports."""
    report_hash: Optional[str] = Field(
        default=None,
        description="Hex-encoded 32-byte cryptographic hash of the canonical report"
    )
    blockchain_network: Optional[str] = Field(
        default=None,
        description="Target blockchain (e.g. Sepolia, Hardhat Local, Polygon Amoy)"
    )
    contract_address: Optional[str] = Field(
        default=None,
        description="Address of the deployed ThreatReportRegistry contract"
    )
    transaction_hash: Optional[str] = Field(
        default=None,
        description="Transaction hash of on-chain commitment"
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.NOT_REGISTERED,
        description="Current verification status against on-chain ledger"
    )


class ReportRegistrationRequest(BaseModel):
    """Request to commit an existing persisted off-chain report to the blockchain."""
    report_id: str = Field(
        ...,
        description="Unique identifier of the persisted report to register"
    )


class ReportRegistrationResponse(BaseModel):
    """Result of on-chain hash registration."""
    report_id: str
    report_hash: str = Field(..., description="Canonical hash submitted to contract")
    transaction_hash: str = Field(..., description="Blockchain transaction hash")
    blockchain_network: str
    contract_address: str
    status: str = Field(default="confirmed", description="confirmed or pending")


class ReportVerificationRequest(BaseModel):
    """Request to verify the integrity of a report against the blockchain."""
    report_id: str = Field(..., description="ID of report to verify")
    provided_hash: Optional[str] = Field(
        default=None,
        description="Optional hash provided by client to test against on-chain record"
    )


class ReportVerificationResponse(BaseModel):
    """Verification outcome proving report integrity and tamper-evidence."""
    report_id: str
    computed_canonical_hash: Optional[str] = None
    on_chain_hash: Optional[str] = None
    is_valid: bool = Field(
        ...,
        description="True if computed hash matches on-chain hash exactly; False if tampered"
    )
    registration_timestamp: Optional[str] = None
    block_number: Optional[int] = None
    verification_status: VerificationStatus
    explanation: str = Field(..., description="Explanation of verification result")

