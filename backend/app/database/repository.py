"""CyberShield AI — Database Repository (Part 19)

Persistence operations for Unified Threat Reports using SQLAlchemy.
"""

from datetime import datetime, timezone
import json
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from app.database.models import ThreatReportModel
from app.schemas.threat_report import UnifiedThreatReport, PersistenceMetadata


def save_threat_report(
    db: Session,
    report: UnifiedThreatReport,
    canonical_hash: Optional[str] = None,
) -> ThreatReportModel:
    """Persist or update a UnifiedThreatReport off-chain in the relational database.
    
    Guarantees that canonical hash is never stale (B5-F09) and commits are atomic (B5-F12).
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # Recompute or ensure canonical hash is fresh and non-stale (B5-F09)
    if not canonical_hash:
        from app.services.blockchain.canonical_hash import compute_canonical_report_hash
        canonical_hash = compute_canonical_report_hash(report)

    # Update persistence metadata on report model
    report.persistence_metadata = PersistenceMetadata(
        stored_at=now_iso,
        database_id=report.scan_id,
        retrieval_count=0,
    )

    # Check if record already exists
    stmt = select(ThreatReportModel).where(ThreatReportModel.scan_id == report.scan_id)
    existing = db.execute(stmt).scalar_one_or_none()

    report_json_str = report.model_dump_json()

    try:
        if existing:
            existing.target_type = report.submitted_input.type.value if hasattr(report.submitted_input.type, "value") else str(report.submitted_input.type)
            existing.target_value = report.submitted_input.value
            existing.risk_classification = report.risk.classification.value if hasattr(report.risk.classification, "value") else str(report.risk.classification)
            existing.risk_score = report.risk.score
            # Always synchronize canonical hash to prevent stale hash on update (B5-F09)
            existing.canonical_hash = canonical_hash
            existing.report_json = report_json_str
            db.commit()
            db.refresh(existing)
            return existing

        record = ThreatReportModel(
            scan_id=report.scan_id,
            target_type=report.submitted_input.type.value if hasattr(report.submitted_input.type, "value") else str(report.submitted_input.type),
            target_value=report.submitted_input.value,
            risk_classification=report.risk.classification.value if hasattr(report.risk.classification, "value") else str(report.risk.classification),
            risk_score=report.risk.score,
            canonical_hash=canonical_hash,
            created_at=now_iso,
            report_json=report_json_str,
            retrieval_count=0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as exc:
        db.rollback()
        raise RuntimeError(f"Database persistence failure for scan_id '{report.scan_id}': {exc}") from exc


def get_threat_report_by_id(
    db: Session, scan_id: str, increment_count: bool = True
) -> Optional[UnifiedThreatReport]:
    """Retrieve and deserialize a UnifiedThreatReport by scan_id."""
    stmt = select(ThreatReportModel).where(ThreatReportModel.scan_id == scan_id)
    record = db.execute(stmt).scalar_one_or_none()
    if not record:
        return None

    if increment_count:
        record.retrieval_count += 1
        db.commit()
        db.refresh(record)

    report_dict = json.loads(record.report_json)
    if "persistence_metadata" in report_dict and report_dict["persistence_metadata"]:
        report_dict["persistence_metadata"]["retrieval_count"] = record.retrieval_count

    return UnifiedThreatReport.model_validate(report_dict)


def list_threat_reports(
    db: Session,
    limit: int = 20,
    offset: int = 0,
    classification: Optional[str] = None,
) -> List[UnifiedThreatReport]:
    """Query paginated list of persisted reports with optional risk classification filter."""
    stmt = select(ThreatReportModel).order_by(desc(ThreatReportModel.created_at))

    if classification:
        stmt = stmt.where(ThreatReportModel.risk_classification == classification)

    stmt = stmt.offset(offset).limit(limit)
    records = db.execute(stmt).scalars().all()

    reports: List[UnifiedThreatReport] = []
    for rec in records:
        try:
            report_dict = json.loads(rec.report_json)
            reports.append(UnifiedThreatReport.model_validate(report_dict))
        except Exception:
            continue

    return reports


def get_total_report_count(
    db: Session, classification: Optional[str] = None, exclude_corrupt: bool = True
) -> int:
    """Count total records matching classification filter, excluding corrupted records (B5-F10)."""
    stmt = select(ThreatReportModel)
    if classification:
        stmt = stmt.where(ThreatReportModel.risk_classification == classification)
    records = db.execute(stmt).scalars().all()
    if not exclude_corrupt:
        return len(records)

    valid_count = 0
    for rec in records:
        try:
            json.loads(rec.report_json)
            valid_count += 1
        except Exception:
            continue
    return valid_count


def update_blockchain_metadata(
    db: Session,
    scan_id: str,
    canonical_hash: str,
    tx_hash: str,
    status: str = "confirmed",
) -> Optional[ThreatReportModel]:
    """Update on-chain registration status and transaction details in DB atomically (B5-F11)."""
    stmt = select(ThreatReportModel).where(ThreatReportModel.scan_id == scan_id)
    record = db.execute(stmt).scalar_one_or_none()
    if not record:
        return None

    now_iso = datetime.now(timezone.utc).isoformat()

    # Validate and update embedded JSON FIRST before modifying column state (B5-F11)
    try:
        data = json.loads(record.report_json)
        if "report_integrity" in data:
            data["report_integrity"]["report_hash"] = canonical_hash
            data["report_integrity"]["transaction_hash"] = tx_hash
            data["report_integrity"]["verification_status"] = (
                "simulated_valid" if status == "simulated" else "verified_valid"
            )
        updated_json = json.dumps(data)
    except Exception as exc:
        db.rollback()
        raise ValueError(f"Failed to synchronize embedded report JSON with blockchain metadata: {exc}") from exc

    try:
        record.canonical_hash = canonical_hash
        record.on_chain_tx_hash = tx_hash
        record.on_chain_status = status
        record.registered_at = now_iso
        record.report_json = updated_json
        db.commit()
        db.refresh(record)
        return record
    except Exception as exc:
        db.rollback()
        raise RuntimeError(f"Database commit failed during blockchain metadata update: {exc}") from exc

