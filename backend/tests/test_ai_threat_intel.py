"""CyberShield AI — Part 18 AI & Threat Intelligence Integration Tests

Tests AI scam analysis heuristics, artifact extraction, fallback handling,
multi-provider threat intelligence aggregation, provider timeout/error resilience,
and integration into the unified risk report pipeline.
"""

import pytest
from app.schemas.ai_analysis import MessageAnalysisRequest
from app.schemas.common import RiskClassification
from app.services.ai_analysis import analyze_scam_message, extract_indicators_from_text
from app.services.threat_intelligence import lookup_threat_intelligence
from app.services.report_generator import assemble_unified_threat_report


class TestAIScamAnalysis:
    """Tests for AI Scam & Social Engineering Message Analysis."""

    def test_credential_phishing_message(self):
        """Verify credential phishing with urgency and bank impersonation triggers high_risk."""
        req = MessageAnalysisRequest(
            message_text="URGENT: Your Chase bank account is suspended. Verify your OTP at https://secure-chase-auth.xyz/login immediately to avoid permanent closure.",
            sender_hint="security-alert@gmail.com",
        )
        res = analyze_scam_message(req)

        assert res.risk_level == "high_risk"
        assert res.category in ("credential_harvesting", "account_takeover_phishing")
        assert res.confidence is not None and res.confidence >= 0.70
        assert len(res.observed_indicators) >= 2
        assert len(res.recommendations) > 0
        assert len(res.limitations) > 0

        # Artifact extraction verification
        assert "https://secure-chase-auth.xyz/login" in res.extracted_indicators.urls
        assert any("chase" in d for d in res.extracted_indicators.domains)

        # Sender mismatch detection
        mismatch_indicators = [
            ind for ind in res.observed_indicators if "Mismatch" in ind.indicator
        ]
        assert len(mismatch_indicators) == 1

    def test_lottery_prize_lure_message(self):
        """Verify advance fee / lottery scam detection."""
        req = MessageAnalysisRequest(
            message_text="Congratulations! You won the international lottery prize of $1,000,000. Claim your prize immediately.",
        )
        res = analyze_scam_message(req)

        assert res.risk_level in ("high_risk", "suspicious")
        assert res.category in ("advance_fee_fraud", "suspicious_message")
        assert any("Prize" in ind.indicator for ind in res.observed_indicators)

    def test_benign_message(self):
        """Verify benign daily text evaluates as low_risk with no active indicators."""
        req = MessageAnalysisRequest(
            message_text="Hey team, the sprint retro meeting has been rescheduled to Thursday at 3 PM. Let me know if that works.",
        )
        res = analyze_scam_message(req)

        assert res.risk_level == "low_risk"
        assert res.category == "benign_informational"
        assert len(res.observed_indicators) == 0
        assert res.confidence == 0.85

    def test_artifact_extraction(self):
        """Verify robust extraction of URLs, emails, and phone numbers."""
        text = (
            "Contact admin@secure-login.test or call (800) 555-0199 or +1-800-555-0123. "
            "Visit https://login.secure-portal.com/auth and http://backup-site.org for details."
        )
        extracted = extract_indicators_from_text(text)

        assert len(extracted.urls) == 2
        assert "admin@secure-login.test" in extracted.emails
        assert len(extracted.phone_numbers) >= 1
        assert "login.secure-portal.com" in extracted.domains
        assert "backup-site.org" in extracted.domains


class TestThreatIntelligenceIntegration:
    """Tests for multi-provider threat intelligence aggregation and resilience."""

    def test_known_malicious_domain_match(self):
        """Verify authoritative threat match on known malicious test targets."""
        summary = lookup_threat_intelligence("https://badurl.com/login.php")

        assert summary.total_sources_queried >= 3
        assert summary.has_authoritative_match is True
        assert summary.matched_sources_count >= 1

        matches = [s for s in summary.sources if s.match]
        assert len(matches) >= 1
        assert matches[0].threat_type is not None
        assert len(matches[0].evidence) > 0

    def test_benign_domain_no_match(self):
        """Verify clean target returns zero matches with proper limitations."""
        summary = lookup_threat_intelligence("https://example.com/index.html")

        assert summary.total_sources_queried >= 3
        assert summary.has_authoritative_match is False
        assert summary.matched_sources_count == 0

        # Non-match must carry cautionary limitations
        for s in summary.sources:
            assert len(s.limitations) > 0

    def test_simulated_provider_timeout_resilience(self):
        """Verify provider timeout does not crash the service and records status='timeout'."""
        summary = lookup_threat_intelligence(
            "https://test-site.org",
            simulate_provider_error="URLhaus",
        )

        urlhaus_source = next((s for s in summary.sources if s.source == "URLhaus"), None)
        assert urlhaus_source is not None
        assert urlhaus_source.source_status == "timeout"
        assert urlhaus_source.match is False
        assert any("timed out" in lim for lim in urlhaus_source.limitations)

    def test_simulated_provider_error_resilience(self):
        """Verify provider error does not crash the service and records status='error'."""
        summary = lookup_threat_intelligence(
            "https://test-site.org",
            simulate_provider_error="Google Safe Browsing",
        )

        gsb_source = next((s for s in summary.sources if s.source == "Google Safe Browsing"), None)
        assert gsb_source is not None
        assert gsb_source.source_status == "error"
        assert gsb_source.match is False


class TestE2EReportIntegrationWithAIAndTI:
    """Tests end-to-end integration into assemble_unified_threat_report."""

    def test_report_assembly_with_ti_malicious_match(self):
        """When threat intelligence detects a match, report classification escalates to CONFIRMED_MALICIOUS."""
        ti_summary = lookup_threat_intelligence("https://malware-drop.test")
        report = assemble_unified_threat_report(
            target="https://malware-drop.test",
            threat_intel=ti_summary,
        )

        assert report.risk.classification == RiskClassification.CONFIRMED_MALICIOUS
        assert report.risk.score is not None and report.risk.score >= 90
        assert len(report.threat_intelligence) >= 3
        assert any(t.match for t in report.threat_intelligence)

    def test_report_assembly_with_ai_message(self):
        """Verify AI analysis is cleanly attached to UnifiedThreatReport."""
        ai_req = MessageAnalysisRequest(
            message_text="URGENT: Your account is suspended. Verify credentials at https://auth-check.xyz immediately.",
        )
        ai_res = analyze_scam_message(ai_req)

        report = assemble_unified_threat_report(
            target="https://auth-check.xyz",
            ai_analysis=ai_res,
        )

        assert report.ai_analysis is not None
        assert report.ai_analysis.risk_level == "high_risk"
        assert report.ai_analysis.category in ("credential_harvesting", "account_takeover_phishing")
