"""CyberShield AI — Part 19 Database & Blockchain Integration Tests

Tests SQLite persistence of Unified Threat Reports, pagination, retrieval tracking,
canonical RFC 8785-compliant report hashing, on-chain hash registration,
and tamper detection through integrity verification.
"""

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base, ThreatReportModel
from app.database.repository import (
    save_threat_report,
    get_threat_report_by_id,
    list_threat_reports,
    get_total_report_count,
)
from app.schemas.common import RiskClassification, VerificationStatus, ScanType
from app.schemas.blockchain import (
    ReportRegistrationRequest,
    ReportVerificationRequest,
)
from app.services.blockchain import (
    compute_canonical_report_hash,
    register_threat_report_on_chain,
    verify_threat_report_integrity,
)
from app.services.report_generator import assemble_unified_threat_report


@pytest.fixture
def in_memory_db():
    """Create isolated in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


class TestCanonicalReportHashing:
    """Tests for deterministic SHA-256 canonical report hashing."""

    def test_canonical_hash_structure(self):
        """Hash must be 66-character hex string starting with 0x."""
        report = assemble_unified_threat_report("https://test-hashing.example.com")
        h = compute_canonical_report_hash(report)

        assert h.startswith("0x")
        assert len(h) == 66
        # Without 0x prefix
        h_raw = compute_canonical_report_hash(report, prefix_0x=False)
        assert len(h_raw) == 64
        assert not h_raw.startswith("0x")

    def test_idempotent_hash_across_invocations(self):
        """Identical reports produce identical canonical hashes."""
        report1 = assemble_unified_threat_report("https://target.test", scan_id="test-id-12345")
        report2 = assemble_unified_threat_report("https://target.test", scan_id="test-id-12345")

        # Set same timestamps to isolate content comparison
        report1.timestamp = "2026-11-08T00:00:00Z"
        report2.timestamp = "2026-11-08T00:00:00Z"
        report1.submitted_input.normalized_at = "2026-11-08T00:00:00Z"
        report2.submitted_input.normalized_at = "2026-11-08T00:00:00Z"

        h1 = compute_canonical_report_hash(report1)
        h2 = compute_canonical_report_hash(report2)
        assert h1 == h2

    def test_mutable_fields_exclusion_from_hash(self):
        """Changes to persistence_metadata or report_integrity do NOT alter the canonical hash."""
        report = assemble_unified_threat_report("https://immutable-check.test")
        base_hash = compute_canonical_report_hash(report)

        # Mutate persistence_metadata
        report.persistence_metadata = type(report.persistence_metadata)(
            stored_at="2026-11-08T12:00:00Z",
            database_id="db-9999",
            retrieval_count=42,
        ) if report.persistence_metadata else None
        assert compute_canonical_report_hash(report) == base_hash

        # Mutate report_integrity
        report.report_integrity.verification_status = VerificationStatus.VERIFIED_VALID
        report.report_integrity.transaction_hash = "0x1234567890abcdef"
        report.report_integrity.report_hash = "0x987654321"
        assert compute_canonical_report_hash(report) == base_hash

    def test_content_mutation_alters_hash(self):
        """Altering a security finding or risk classification changes the canonical hash."""
        report = assemble_unified_threat_report("https://tamper-check.test")
        original_hash = compute_canonical_report_hash(report)

        # Tamper with risk classification
        report.risk.classification = RiskClassification.LOW_RISK
        tampered_hash = compute_canonical_report_hash(report)
        assert tampered_hash != original_hash


class TestDatabasePersistence:
    """Tests for SQLite database persistence and retrieval."""

    def test_save_and_retrieve_report(self, in_memory_db):
        """Save a UnifiedThreatReport and verify clean retrieval."""
        report = assemble_unified_threat_report("https://persist-test.example.com")
        save_threat_report(in_memory_db, report)

        retrieved = get_threat_report_by_id(in_memory_db, report.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == report.scan_id
        assert retrieved.submitted_input.value == report.submitted_input.value
        assert retrieved.risk.classification == report.risk.classification
        assert retrieved.persistence_metadata is not None
        assert retrieved.persistence_metadata.retrieval_count == 1

        # Second retrieval increments counter
        retrieved_again = get_threat_report_by_id(in_memory_db, report.scan_id)
        assert retrieved_again.persistence_metadata.retrieval_count == 2

    def test_list_and_paginate_reports(self, in_memory_db):
        """Test report listing, pagination, and classification filtering."""
        for i in range(5):
            rep = assemble_unified_threat_report(f"https://site-{i}.test")
            save_threat_report(in_memory_db, rep)

        reports = list_threat_reports(in_memory_db, limit=3, offset=0)
        assert len(reports) == 3

        total = get_total_report_count(in_memory_db)
        assert total == 5

    def test_nonexistent_report_returns_none(self, in_memory_db):
        """Querying unknown scan_id returns None."""
        assert get_threat_report_by_id(in_memory_db, "nonexistent-scan-id") is None


class TestBlockchainRegistrationAndVerification:
    """Tests for on-chain registration and tamper-detection verification."""

    def test_register_and_verify_valid_report(self, in_memory_db):
        """Register report on-chain and verify its cryptographic integrity."""
        report = assemble_unified_threat_report("https://valid-on-chain.test")
        save_threat_report(in_memory_db, report)

        # 1. On-chain registration
        reg_req = ReportRegistrationRequest(report_id=report.scan_id)
        reg_res = register_threat_report_on_chain(reg_req, in_memory_db)

        assert reg_res.report_id == report.scan_id
        assert reg_res.status in ("simulated", "confirmed")
        assert reg_res.report_hash.startswith("0x")
        assert "simulated_tx:" in reg_data_tx if hasattr(reg_res, "transaction_hash") and (reg_data_tx := reg_res.transaction_hash) else reg_res.transaction_hash.startswith("0x")

        # 2. Verification
        ver_req = ReportVerificationRequest(report_id=report.scan_id)
        ver_res = verify_threat_report_integrity(ver_req, in_memory_db)

        assert ver_res.is_valid is True
        assert ver_res.verification_status in (VerificationStatus.SIMULATED_VALID, VerificationStatus.VERIFIED_VALID)
        assert ver_res.computed_canonical_hash == reg_res.report_hash
        assert ver_res.on_chain_hash == reg_res.report_hash

    def test_tamper_detection(self, in_memory_db):
        """Tampering with stored report payload results in VERIFIED_TAMPERED."""
        report = assemble_unified_threat_report("https://tamper-target.test")
        save_threat_report(in_memory_db, report)

        # Register on-chain
        reg_req = ReportRegistrationRequest(report_id=report.scan_id)
        reg_res = register_threat_report_on_chain(reg_req, in_memory_db)

        # Tamper directly with the database record JSON payload
        record = in_memory_db.query(ThreatReportModel).filter_by(scan_id=report.scan_id).first()
        tampered_data = json.loads(record.report_json)
        tampered_data["risk"]["classification"] = "Low Risk"
        tampered_data["risk"]["summary"] = "Hacked summary - harmless site!"
        record.report_json = json.dumps(tampered_data)
        in_memory_db.commit()

        # Run verification
        ver_req = ReportVerificationRequest(report_id=report.scan_id)
        ver_res = verify_threat_report_integrity(ver_req, in_memory_db)

        assert ver_res.is_valid is False
        assert ver_res.verification_status in (VerificationStatus.SIMULATED_TAMPERED, VerificationStatus.VERIFIED_TAMPERED)
        assert "TAMPER DETECTED" in ver_res.explanation

    def test_unregistered_report_verification(self, in_memory_db):
        """Unregistered report returns NOT_REGISTERED status."""
        report = assemble_unified_threat_report("https://unregistered.test")
        save_threat_report(in_memory_db, report)

        ver_req = ReportVerificationRequest(report_id=report.scan_id)
        ver_res = verify_threat_report_integrity(ver_req, in_memory_db)

        assert ver_res.is_valid is False
        assert ver_res.verification_status == VerificationStatus.NOT_REGISTERED

    def test_nonexistent_report_verification(self, in_memory_db):
        """Non-existent report returns NOT_FOUND status."""
        ver_req = ReportVerificationRequest(report_id="ghost-id-000")
        ver_res = verify_threat_report_integrity(ver_req, in_memory_db)

        assert ver_res.is_valid is False
        assert ver_res.verification_status == VerificationStatus.NOT_FOUND

    def test_simulated_rpc_failure(self, in_memory_db):
        """Simulated RPC node failure returns failure with diagnostic message."""
        ver_req = ReportVerificationRequest(report_id="any-id")
        ver_res = verify_threat_report_integrity(ver_req, in_memory_db, simulate_rpc_failure=True)

        assert ver_res.is_valid is False
        assert "unreachable or offline" in ver_res.explanation

