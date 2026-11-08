"""CyberShield AI — URL Investigation Service Package (Batch 2: Parts 05–08)

Exports URL validation, normalization, SSRF safety validation, heuristic pattern detection,
and the preflight pipeline service.
"""

from app.services.url_investigation.validation import (
    validate_url_input,
    sanitize_credentials_from_url,
)
from app.services.url_investigation.normalization import (
    normalize_url,
    extract_registrable_domain,
    remove_dot_segments,
    normalize_percent_encoding,
)
from app.services.url_investigation.ssrf_guard import (
    validate_destination_safety,
    evaluate_ip_safety,
    parse_ip_safely,
    resolve_hostname_all_ips,
)
from app.services.url_investigation.heuristics import (
    detect_suspicious_patterns,
    detect_ip_hostname,
    detect_excessive_subdomains,
    detect_deceptive_keywords,
    detect_homograph_and_punycode,
    detect_suspicious_encoding,
    detect_open_redirect_parameters,
    detect_non_standard_port,
    detect_url_shortener,
    detect_excessive_length,
)
from app.services.url_investigation.service import (
    investigate_url_preflight,
)

__all__ = [
    "validate_url_input",
    "sanitize_credentials_from_url",
    "normalize_url",
    "extract_registrable_domain",
    "remove_dot_segments",
    "normalize_percent_encoding",
    "validate_destination_safety",
    "evaluate_ip_safety",
    "parse_ip_safely",
    "resolve_hostname_all_ips",
    "detect_suspicious_patterns",
    "detect_ip_hostname",
    "detect_excessive_subdomains",
    "detect_deceptive_keywords",
    "detect_homograph_and_punycode",
    "detect_suspicious_encoding",
    "detect_open_redirect_parameters",
    "detect_non_standard_port",
    "detect_url_shortener",
    "detect_excessive_length",
    "investigate_url_preflight",
]

