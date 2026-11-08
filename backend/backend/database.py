"""Backward-compatible database adapter for modules importing from backend.database."""
from app.database import (
    Base,
    ThreatReportModel,
    engine,
    SessionLocal,
    init_db,
    get_db,
    save_threat_report,
    get_threat_report_by_id,
    list_threat_reports,
    get_total_report_count,
    update_blockchain_metadata,
)

__all__ = [
    "Base",
    "ThreatReportModel",
    "engine",
    "SessionLocal",
    "init_db",
    "get_db",
    "save_threat_report",
    "get_threat_report_by_id",
    "list_threat_reports",
    "get_total_report_count",
    "update_blockchain_metadata",
]

