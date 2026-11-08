"""CyberShield AI — DNS Investigation Module (Part 09)"""

from app.services.dns.models import DNSInvestigationResult, DNSStatus
from app.services.dns.service import investigate_dns, resolve_a_and_aaaa_records, query_dns_record_type

__all__ = [
    "DNSInvestigationResult",
    "DNSStatus",
    "investigate_dns",
    "resolve_a_and_aaaa_records",
    "query_dns_record_type",
]

