"""CyberShield AI — Unified URL & Domain Scanner Service

Coordinates:
- Member 1: Intake validation, normalization, SSRF Security Guard, Stage 3 Technical Website Investigation (DNS, Redirects, TLS, Security Headers), and UnifiedThreatReport generation.
- Member 4: Live Threat Intelligence queries (URLhaus, PhishTank), safe defanging, and reputation evaluation.
- Member 3: Cryptographic canonical hashing and on-chain blockchain anchoring on ThreatReportRegistry.
- Relational persistence into both Member 1's `ThreatReportModel` and Member 4's `Scan`/`RiskReport` tables.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import Scan, IntelligenceResult, RiskReport, ScanEvent
from app.database.repository import save_threat_report
from app.schemas.scan import ScanDetailResponse, ScanEventSchema, RiskReportSchema, ProviderResultSchema
from app.schemas.common import ScanType, RiskClassification
from app.services.blockchain_verifier import ReportVerifier
from app.services.blockchain.adapter import threat_report_to_canonical_blockchain_dict
from app.services.blockchain.canonical_hash import compute_canonical_report_hash
from app.services.url_investigation import investigate_url_preflight
from app.services.technical_investigation import investigate_technical_website
from app.services.threat_intelligence.service import lookup_threat_intelligence
from app.services.report_generator.builder import assemble_unified_threat_report
from threat_intel.normalization import URLNormalizer
from threat_intel.providers.urlhaus import URLhausProvider
from threat_intel.providers.phishtank import PhishTankProvider
from threat_intel.services.reputation import ReputationAssessor
from threat_intel.services.normalizer import IndicatorNormalizer

logger = logging.getLogger("cybershield.scanner")


class ScannerService:
    """Orchestrates comprehensive multi-member URL threat investigation."""

    @staticmethod
    async def scan_url(raw_target: str, db: Session) -> ScanDetailResponse:
        # 1. Normalize and Validate Input Target
        meta = URLNormalizer.normalize_target(raw_target)
        normalized_url = meta["normalized_url"]

        # 2. Create Initial Relational Scan Entry
        scan = Scan(
            scan_type="url",
            target=raw_target,
            status="in_progress",
            risk_level="Unknown",
            risk_score=0
        )
        db.add(scan)
        db.flush()

        # Add initial normalization audit event
        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="normalization",
            description=f"Target validated and normalized to '{normalized_url}'."
        ))
        db.commit()

        # 3. Member 1 SSRF Security Guard & Preflight Verification
        preflight = investigate_url_preflight(raw_target)
        is_blocked = (not preflight.is_eligible_for_scan) or (not preflight.validation.is_valid)

        if is_blocked:
            # Destination safety violation (SSRF, loopback, private IP, metadata address)
            reason = preflight.ssrf_check.reason or "SSRF Security Guard: Target blocked by destination safety policy."
            db.add(ScanEvent(
                scan_id=scan.id,
                event_type="security_gate",
                description=f"Outbound investigation blocked by SSRF Security Guard: {reason}"
            ))

            summary = f"Outbound investigation blocked by SSRF Security Guard: {reason}"
            evidence = [
                f"SSRF Security Guard blocked outbound requests for '{raw_target}'.",
                f"Destination safety violation: {reason}",
                "Outbound HTTP/DNS scanning aborted to protect internal perimeter."
            ]
            recommendations = [
                "Do not submit internal loopback or private infrastructure addresses for public external scanning.",
                "Verify input URL belongs to an authoritative public domain."
            ]

            risk_level = "Critical"
            risk_score = 95

            # Assemble M1 Unified Threat Report
            m1_report = assemble_unified_threat_report(
                target=raw_target,
                target_type=ScanType.URL,
                preflight=preflight,
                custom_limitations=["Outbound technical investigation omitted due to SSRF safety block or invalid syntax."]
            )
            canonical_hash = compute_canonical_report_hash(m1_report)
            save_threat_report(db, m1_report, canonical_hash=canonical_hash)

            # Store Member 4 Risk Report
            report = RiskReport(
                scan_id=scan.id,
                summary=summary,
                evidence=json.dumps(evidence),
                recommendations=json.dumps(recommendations),
                report_hash=canonical_hash,
                verification_status="locally_hashed",
                blockchain_tx=None
            )
            db.add(report)

            scan.status = "completed"
            scan.risk_level = risk_level
            scan.risk_score = risk_score
            db.commit()
            db.refresh(scan)
            db.refresh(report)

            return ScanDetailResponse(
                scan_id=scan.id,
                scan_type=scan.scan_type,
                target=scan.target,
                normalized_target=normalized_url,
                domain=meta.get("domain"),
                hostname=meta.get("hostname"),
                status=scan.status,
                risk_level=scan.risk_level,
                risk_score=scan.risk_score,
                created_at=scan.created_at,
                providers_checked=[],
                report=RiskReportSchema(
                    report_id=report.id,
                    summary=report.summary,
                    evidence=evidence,
                    recommendations=recommendations,
                    report_hash=report.report_hash,
                    verification_status=report.verification_status,
                    blockchain_tx=report.blockchain_tx,
                    created_at=report.created_at
                ),
                events=[
                    ScanEventSchema(
                        event_type=e.event_type,
                        description=e.description,
                        created_at=e.created_at
                    ) for e in scan.events
                ]
            )

        # 4. Safe Outbound Technical Investigation (DNS, Redirects, TLS, Security Headers)
        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="technical_investigation",
            description="Initiating Stage 3 technical forensics: DNS resolution, multi-hop redirect tracing, TLS certificate inspection, and HTTP security headers."
        ))
        db.commit()

        technical = investigate_technical_website(raw_target)

        # 5. Query Threat Intelligence Feeds in parallel (URLhaus, PhishTank, M1 Threat Intel)
        urlhaus = URLhausProvider()
        phishtank = PhishTankProvider()

        ti_results = await asyncio.gather(
            urlhaus.query_url(normalized_url),
            phishtank.query_url(normalized_url),
            return_exceptions=True
        )

        indicators = []
        for r in ti_results:
            if isinstance(r, Exception):
                logger.error(f"Threat intel query exception: {r}")
            else:
                indicators.append(r)

        # Save Intelligence Results to DB
        db_indicators = []
        for ind in indicators:
            db_res = IntelligenceResult(
                scan_id=scan.id,
                provider=ind.provider,
                indicator_type=ind.indicator_type,
                indicator_value=ind.indicator_value,
                status=ind.status,
                matched=ind.matched,
                verified=ind.verified,
                reference=ind.reference,
                details=json.dumps(ind.details),
                first_seen=ind.first_seen,
                last_seen=ind.last_seen
            )
            db.add(db_res)
            db_indicators.append(db_res)

        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="provider_query",
            description=f"Queried {len(indicators)} intelligence feeds ({', '.join(ind.provider for ind in indicators)})."
        ))
        db.flush()

        # 6. Evaluate Multi-Factor Risk Assessment
        assessment = ReputationAssessor.evaluate(meta, indicators)

        # Also pull Member 1 Threat Intel for unified aggregation
        m1_ti = lookup_threat_intelligence(raw_target)

        # 7. Assemble Unified Threat Report
        m1_report = assemble_unified_threat_report(
            target=raw_target,
            target_type=ScanType.URL,
            preflight=preflight,
            technical_investigation=technical,
            threat_intel=m1_ti
        )

        # 8. Compute Cryptographic Canonical Hashes
        canonical_m3_dict = threat_report_to_canonical_blockchain_dict(m1_report)
        canonical_hash = compute_canonical_report_hash(m1_report)

        # Build combined evidence list
        evidence_list = list(assessment.evidence)
        for finding in technical.all_findings:
            evidence_list.append(f"{finding.title}: {finding.description}")

        # Derive final risk classification and score
        m1_score = m1_report.risk.score or 0
        final_risk_score = max(assessment.risk_score, m1_score)
        if final_risk_score >= 80:
            final_risk_level = "Critical"
        elif final_risk_score >= 60:
            final_risk_level = "High"
        elif final_risk_score >= 35:
            final_risk_level = "Medium"
        else:
            final_risk_level = "Low"

        # 9. Build canonical payload & cryptographic proof for RiskReport
        canonical_dict = ReportVerifier.build_canonical_payload(
            scan_id=scan.id,
            target=raw_target,
            risk_level=final_risk_level,
            risk_score=final_risk_score,
            summary=assessment.summary,
            evidence=evidence_list,
            recommendations=assessment.recommendations
        )
        risk_report_hash = ReportVerifier.calculate_hash(canonical_dict)

        # 10. Blockchain Anchoring via Member 3 Web3 Client
        verification_status, tx_hash = await ReportVerifier.anchor_on_blockchain(
            canonical_hash, canonical_m3_dict
        )

        # 11. Persist Member 1 UnifiedThreatReport
        save_threat_report(db, m1_report, canonical_hash=canonical_hash)

        # 12. Persist Member 4 RiskReport
        report = RiskReport(
            scan_id=scan.id,
            summary=assessment.summary,
            evidence=json.dumps(evidence_list),
            recommendations=json.dumps(assessment.recommendations),
            report_hash=risk_report_hash,
            verification_status=verification_status,
            blockchain_tx=tx_hash
        )
        db.add(report)

        # 12. Finalize Scan Record
        scan.status = "completed"
        scan.risk_level = final_risk_level
        scan.risk_score = final_risk_score

        db.add(ScanEvent(
            scan_id=scan.id,
            event_type="report_generation",
            description=f"Generated report with cryptographic hash proof: {canonical_hash[:16]}... (Status: {verification_status})"
        ))
        db.commit()
        db.refresh(scan)
        db.refresh(report)

        return ScanDetailResponse(
            scan_id=scan.id,
            scan_type=scan.scan_type,
            target=scan.target,
            normalized_target=normalized_url,
            domain=meta.get("domain"),
            hostname=meta.get("hostname"),
            status=scan.status,
            risk_level=scan.risk_level,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
            providers_checked=IndicatorNormalizer.list_to_schema(indicators),
            report=RiskReportSchema(
                report_id=report.id,
                summary=report.summary,
                evidence=evidence_list,
                recommendations=assessment.recommendations,
                report_hash=report.report_hash,
                verification_status=report.verification_status,
                blockchain_tx=report.blockchain_tx,
                created_at=report.created_at
            ),
            events=[
                ScanEventSchema(
                    event_type=e.event_type,
                    description=e.description,
                    created_at=e.created_at
                ) for e in scan.events
            ]
        )
