"""Unit and Integration Tests for CyberShield AI Blockchain Module (Member 3 Integrated)

Tests cover:
  - Input validation & normalization (10 required fields)
  - Decimal and integer numeric precision
  - Canonical JSON serialization
  - Argument compatibility: hash_report(raw) & hash_report(type, raw)
  - Transaction receipt failure handling
  - Tamper detection
"""

import copy
import math
import pytest
from unittest.mock import MagicMock, patch

from app.services.blockchain.report_hash import (
    SAMPLE_REPORT,
    canonicalize_report,
    generate_report_hash,
    generate_report_id,
    hash_report,
    normalize_number,
    normalize_threat_report,
    validate_threat_report,
)
from app.services.blockchain.service import BlockchainService, BlockchainTransactionError


# ─────────────────────────────────────────────────────────────────
#  1. Validation & Required Fields Tests
# ─────────────────────────────────────────────────────────────────

class TestReportValidation:
    """Tests strict validation of UnifiedThreatReport required fields and types."""

    def test_valid_sample_report(self):
        """Standard valid sample report passes validation without error."""
        validated = validate_threat_report(SAMPLE_REPORT)
        assert validated["report_id"] == "CSR-20261107-00001"

    @pytest.mark.parametrize("missing_field", [
        "report_id", "schema_version", "detected_at", "generated_at",
        "severity", "category", "status", "confidence_score",
        "summary", "description"
    ])
    def test_missing_required_field_raises(self, missing_field):
        """Omitting any of the 10 required fields must raise ValueError."""
        report = copy.deepcopy(SAMPLE_REPORT)
        del report[missing_field]
        with pytest.raises(ValueError, match=f"Missing required report fields:.*{missing_field}"):
            validate_threat_report(report)

    def test_none_value_for_required_field_raises(self):
        """Required field set to None raises ValueError."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["summary"] = None
        with pytest.raises(ValueError, match="Missing required report fields:.*summary"):
            validate_threat_report(report)

    def test_non_dict_input_raises_type_error(self):
        """Passing non-dictionary to validate_threat_report raises TypeError."""
        with pytest.raises(TypeError, match="must be a dictionary"):
            validate_threat_report(["not", "a", "dict"])

    @pytest.mark.parametrize("invalid_sev", ["extreme", "urgent", "catastrophic", ""])
    def test_invalid_severity_raises(self, invalid_sev):
        """Severity outside allowed enum set raises ValueError."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["severity"] = invalid_sev
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_threat_report(report)

    @pytest.mark.parametrize("valid_sev", ["critical", "high", "medium", "low", "informational", "unknown"])
    def test_all_valid_severities_accepted(self, valid_sev):
        """All documented severities are accepted."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["severity"] = valid_sev
        assert validate_threat_report(report)["severity"] == valid_sev

    @pytest.mark.parametrize("invalid_cat", ["financial", "espionage", "alien_attack", ""])
    def test_invalid_category_raises(self, invalid_cat):
        """Category outside allowed enum set raises ValueError."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["category"] = invalid_cat
        with pytest.raises(ValueError, match="Invalid category"):
            validate_threat_report(report)

    @pytest.mark.parametrize("invalid_status", ["done", "pending", "closed", ""])
    def test_invalid_status_raises(self, invalid_status):
        """Status outside allowed enum set raises ValueError."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["status"] = invalid_status
        with pytest.raises(ValueError, match="Invalid status"):
            validate_threat_report(report)

    @pytest.mark.parametrize("bad_ts", [
        "2026-11-07",
        "10:00:00",
        "yesterday",
        "2026/11/07 10:00:00",
    ])
    def test_invalid_timestamp_raises(self, bad_ts):
        """Non-ISO-8601 timestamps must be rejected."""
        report = copy.deepcopy(SAMPLE_REPORT)
        report["detected_at"] = bad_ts
        with pytest.raises(ValueError, match="not a valid ISO-8601 timestamp"):
            validate_threat_report(report)

    def test_empty_string_fields_raise(self):
        """Empty string report_id, summary, or description must raise ValueError."""
        for f in ["report_id", "summary", "description"]:
            report = copy.deepcopy(SAMPLE_REPORT)
            report[f] = "   "
            with pytest.raises(ValueError, match=f"cannot be empty"):
                validate_threat_report(report)


# ─────────────────────────────────────────────────────────────────
#  2. Numeric Normalization Tests
# ─────────────────────────────────────────────────────────────────

class TestNumericNormalization:
    """Tests cross-language number normalization matching JavaScript."""

    def test_integer_preserved(self):
        assert normalize_number(87) == 87
        assert isinstance(normalize_number(87), int)

    def test_whole_float_normalized_to_int(self):
        """87.0 float becomes int 87 to match JavaScript serialization."""
        result = normalize_number(87.0)
        assert result == 87
        assert isinstance(result, int)

    def test_fractional_float_preserved(self):
        """87.5 float remains float 87.5."""
        result = normalize_number(87.5)
        assert result == 87.5
        assert isinstance(result, float)

    def test_boundary_values(self):
        assert normalize_number(0) == 0
        assert normalize_number(100) == 100
        assert normalize_number(0.0) == 0
        assert normalize_number(100.0) == 100

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError, match="out of range"):
            normalize_number(-1)
        with pytest.raises(ValueError, match="out of range"):
            normalize_number(101)

    def test_boolean_rejected(self):
        """Booleans must not be accepted as numbers."""
        with pytest.raises(ValueError, match="must be a number, not boolean"):
            normalize_number(True)
        with pytest.raises(ValueError, match="must be a number, not boolean"):
            normalize_number(False)

    def test_nan_and_inf_rejected(self):
        with pytest.raises(ValueError, match="must not be NaN or Infinity"):
            normalize_number(float("nan"))
        with pytest.raises(ValueError, match="must not be NaN or Infinity"):
            normalize_number(float("inf"))


# ─────────────────────────────────────────────────────────────────
#  3. Hash Function Signature Compatibility
# ─────────────────────────────────────────────────────────────────

class TestHashFunctionCompatibility:
    """Verifies hash_report() accepts both 1-arg and 2-arg patterns."""

    def test_single_arg_pattern(self):
        """hash_report(raw_report) returns (bytes32, bytes32)."""
        rh, rid = hash_report(SAMPLE_REPORT)
        assert isinstance(rh, bytes) and len(rh) == 32
        assert isinstance(rid, bytes) and len(rid) == 32

    def test_two_arg_pattern(self):
        """hash_report(report_type, raw_report) returns (bytes32, bytes32)."""
        rh, rid = hash_report("threat_report", SAMPLE_REPORT)
        assert isinstance(rh, bytes) and len(rh) == 32
        assert isinstance(rid, bytes) and len(rid) == 32

    def test_both_patterns_produce_identical_hash(self):
        """Both argument patterns must produce the exact same hash and ID."""
        rh1, rid1 = hash_report(SAMPLE_REPORT)
        rh2, rid2 = hash_report("threat_report", SAMPLE_REPORT)
        assert rh1 == rh2
        assert rid1 == rid2

    def test_invalid_args_raises_type_error(self):
        with pytest.raises(TypeError, match="Invalid arguments to hash_report"):
            hash_report("just_a_string")


# ─────────────────────────────────────────────────────────────────
#  4. Canonical Serialization & Tamper Detection
# ─────────────────────────────────────────────────────────────────

class TestCanonicalHashing:
    """Tests deterministic hashing and tamper detection."""

    def test_deterministic_hash_production(self):
        """Two calls with identical reports produce the exact same hash."""
        rh1, rid1 = hash_report(SAMPLE_REPORT)
        rh2, rid2 = hash_report(copy.deepcopy(SAMPLE_REPORT))
        assert rh1 == rh2
        assert rid1 == rid2

    def test_key_order_independence(self):
        """Key insertion order must not affect the resulting hash."""
        report_reversed = dict(reversed(list(SAMPLE_REPORT.items())))
        rh_orig, _ = hash_report(SAMPLE_REPORT)
        rh_rev, _ = hash_report(report_reversed)
        assert rh_orig == rh_rev

    def test_tamper_detected_on_score_change(self):
        """Modifying confidence_score changes the hash."""
        tampered = copy.deepcopy(SAMPLE_REPORT)
        tampered["confidence_score"] = 99
        rh_orig, _ = hash_report(SAMPLE_REPORT)
        rh_tamp, _ = hash_report(tampered)
        assert rh_orig != rh_tamp

    def test_tamper_detected_on_indicator_change(self):
        """Adding or modifying an indicator changes the hash."""
        tampered = copy.deepcopy(SAMPLE_REPORT)
        tampered["indicators"].append({"ioc_type": "ip", "value": "192.0.2.1"})
        rh_orig, _ = hash_report(SAMPLE_REPORT)
        rh_tamp, _ = hash_report(tampered)
        assert rh_orig != rh_tamp

    def test_tamper_detected_on_remediation_change(self):
        """Changing remediation priority changes the hash."""
        tampered = copy.deepcopy(SAMPLE_REPORT)
        tampered["remediation_steps"][0]["priority"] = 99
        rh_orig, _ = hash_report(SAMPLE_REPORT)
        rh_tamp, _ = hash_report(tampered)
        assert rh_orig != rh_tamp


# ─────────────────────────────────────────────────────────────────
#  5. Transaction Receipt Validation
# ─────────────────────────────────────────────────────────────────

class TestTransactionReceiptValidation:
    """Tests that BlockchainService validates transaction receipts."""

    @patch("app.services.blockchain.service.Web3")
    def test_failed_receipt_status_raises_error(self, mock_web3_class):
        """When receipt.status == 0, BlockchainTransactionError must be raised."""
        mock_w3 = MagicMock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.eth.accounts = ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.gas_price = 1_000_000_000
        mock_w3.eth.send_transaction.return_value = bytes.fromhex("ab" * 32)

        # Mock receipt with status 0 (failed/reverted transaction)
        mock_receipt = MagicMock()
        mock_receipt.status = 0
        mock_receipt.blockNumber = 42
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        svc = BlockchainService(
            rpc_url="http://127.0.0.1:8545",
            contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            private_key=None,
        )

        with pytest.raises(BlockchainTransactionError, match="reverted on-chain"):
            svc.register_report(SAMPLE_REPORT)

    @patch("app.services.blockchain.service.Web3")
    def test_successful_receipt_status_returns_dict(self, mock_web3_class):
        """When receipt.status == 1, registration succeeds with receipt metadata."""
        mock_w3 = MagicMock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.eth.accounts = ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
        mock_w3.eth.get_transaction_count.return_value = 1
        mock_w3.eth.gas_price = 1_000_000_000
        mock_w3.eth.send_transaction.return_value = bytes.fromhex("cd" * 32)

        # Mock successful receipt
        mock_receipt = MagicMock()
        mock_receipt.status = 1
        mock_receipt.blockNumber = 100
        mock_receipt.gasUsed = 65000
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        svc = BlockchainService(
            rpc_url="http://127.0.0.1:8545",
            contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
            private_key=None,
        )

        result = svc.register_report(SAMPLE_REPORT)
        assert result["status"] == "confirmed"
        assert result["block_number"] == 100
        assert result["gas_used"] == 65000
        assert result["report_hash"].startswith("0x")
        assert result["report_id"].startswith("0x")

