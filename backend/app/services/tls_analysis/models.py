"""CyberShield AI — Part 11: TLS & SSL Certificate Analysis Models

Data models and schemas for TLS inspection, certificate details, and cipher evaluation.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.common import TechnicalFinding, TechnicalLimitation
from app.schemas.url_scan import TLSFindingDetails


class TLSStatus(str, Enum):
    """Status classifications for TLS and certificate analysis."""
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    SELF_SIGNED = "SELF_SIGNED"
    HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"
    UNTRUSTED_CHAIN = "UNTRUSTED_CHAIN"
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    TIMEOUT = "TIMEOUT"
    NOT_HTTPS = "NOT_HTTPS"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    UNAVAILABLE = "UNAVAILABLE"


class TLSCertificateInfo(BaseModel):
    """Detailed metadata extracted from an X.509 certificate."""
    subject: Dict[str, str] = Field(default_factory=dict, description="Certificate subject attributes (CN, O, C)")
    issuer: Dict[str, str] = Field(default_factory=dict, description="Certificate issuer attributes (CN, O, C)")
    valid_from: Optional[str] = Field(default=None, description="Not Before UTC timestamp in ISO 8601")
    valid_to: Optional[str] = Field(default=None, description="Not After UTC timestamp in ISO 8601")
    is_expired: bool = Field(default=False, description="Whether certificate validity date is in the past")
    days_to_expiration: Optional[int] = Field(default=None, description="Days remaining until certificate expiry")
    san_list: List[str] = Field(default_factory=list, description="Subject Alternative Names (SANs)")
    san_matches: bool = Field(default=False, description="Whether requested hostname matches SANs or CN")
    serial_number: Optional[str] = Field(default=None, description="Certificate serial number hex")
    version: Optional[int] = Field(default=None, description="X.509 certificate version")
    signature_algorithm: Optional[str] = Field(default=None, description="Signature algorithm if available")


class TLSConnectionInfo(BaseModel):
    """Metadata regarding the negotiated TLS session."""
    tls_version: Optional[str] = Field(default=None, description="Negotiated protocol version (e.g. TLSv1.3)")
    cipher_name: Optional[str] = Field(default=None, description="Negotiated cipher suite name")
    cipher_bits: Optional[int] = Field(default=None, description="Secret key bit strength of cipher")
    alpn_protocol: Optional[str] = Field(default=None, description="Application Layer Protocol Negotiation result")


class TLSAnalysisResult(BaseModel):
    """Complete structured findings from TLS certificate analysis (Part 11)."""
    hostname: str = Field(..., description="Target hostname inspected")
    port: int = Field(default=443, description="Target port number")
    status: TLSStatus = Field(..., description="High-level TLS verification outcome")
    is_valid: bool = Field(default=False, description="Whether certificate passed cryptographic validity checks")
    is_trusted: bool = Field(default=False, description="Whether certificate chains to a trusted root CA")
    certificate: Optional[TLSCertificateInfo] = Field(default=None, description="X.509 certificate metadata")
    connection: Optional[TLSConnectionInfo] = Field(default=None, description="Negotiated session parameters")
    ca_trust_status: str = Field(default="UNKNOWN", description="'TRUSTED_CA', 'SELF_SIGNED', 'UNTRUSTED_CA', or 'UNKNOWN'")
    revocation_status: str = Field(default="NOT_CHECKED_OFFLINE_MODE", description="Revocation check status (OCSP/CRL)")
    certificate_transparency: str = Field(default="UNAVAILABLE_EXTERNAL_LOGS_NOT_QUERIED", description="CT status")
    verification_error: Optional[str] = Field(default=None, description="Underlying verification error if untrusted")
    findings: List[TechnicalFinding] = Field(default_factory=list, description="Structured technical findings")
    limitations: List[TechnicalLimitation] = Field(default_factory=list, description="Documented inspection limitations")

    def to_tls_finding_details(self) -> TLSFindingDetails:
        """Convert into backward-compatible TLSFindingDetails for unified threat reports."""
        subject_str = f"CN={self.certificate.subject.get('commonName', 'Unknown')}" if self.certificate else None
        issuer_str = f"CN={self.certificate.issuer.get('commonName', 'Unknown')}" if self.certificate else None

        return TLSFindingDetails(
            hostname=self.hostname,
            subject=subject_str,
            issuer=issuer_str,
            valid_from=self.certificate.valid_from if self.certificate else None,
            valid_to=self.certificate.valid_to if self.certificate else None,
            is_expired=self.certificate.is_expired if self.certificate else None,
            days_to_expiration=self.certificate.days_to_expiration if self.certificate else None,
            san_matches=self.certificate.san_matches if self.certificate else None,
            san_list=self.certificate.san_list if self.certificate else [],
            weak_algorithm_detected=any(f.check_name == "WEAK_TLS_CONFIGURATION" for f in self.findings),
            ca_trust_status=self.ca_trust_status.lower(),
            certificate_transparency_present=None  # Accurately represented as unqueried offline
        )

