"""CyberShield AI — Part 05: URL Input Validation

Validates untrusted URL inputs strictly before any network activity, normalization,
or downstream investigation. Rejects malformed structures, unsupported schemes,
illegal ports, control characters, and embedded credentials without leaking sensitive
data in logs or error messages.
"""

import re
import urllib.parse
from typing import Optional, Tuple
from app.schemas.url_scan import URLValidationResult

# Prohibited/dangerous schemes (explicit whitelist: http, https only)
ALLOWED_SCHEMES = {"http", "https"}

# Regex for detecting embedded credentials safely
CREDENTIAL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://([^@/]+)@")

# Control character detection (ASCII 0-31 and 127)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Standard maximum length per API contract
MAX_URL_LENGTH = 2048


def sanitize_credentials_from_url(raw_url: str) -> Tuple[str, bool]:
    """Redact embedded credentials (user:pass@) from a URL string.
    
    Returns:
        (sanitized_url, had_credentials)
    """
    if "@" in raw_url:
        match = CREDENTIAL_PATTERN.search(raw_url)
        if match:
            # Replace the credentials segment between scheme:// and @ with [REDACTED_CREDENTIALS]
            scheme_end = raw_url.find("://") + 3
            at_idx = raw_url.find("@", scheme_end)
            if at_idx != -1 and (raw_url.find("/", scheme_end) == -1 or at_idx < raw_url.find("/", scheme_end)):
                sanitized = raw_url[:scheme_end] + "[REDACTED_CREDENTIALS]@" + raw_url[at_idx + 1:]
                return sanitized, True
    return raw_url, False


def validate_url_input(raw_input: Optional[str], max_length: int = MAX_URL_LENGTH) -> URLValidationResult:
    """Validate untrusted URL input before processing.
    
    Enforces strict syntactic, scheme, authority, port, and security boundaries.
    Fails closed on any ambiguity or anomaly.
    
    Args:
        raw_input: The raw user-supplied string.
        max_length: Maximum permitted length in characters.
        
    Returns:
        URLValidationResult detailing validity, components, and safe error details.
    """
    if raw_input is None:
        return URLValidationResult(
            is_valid=False,
            raw_input="",
            error_code="EMPTY_INPUT",
            error_message="URL input cannot be null or empty."
        )

    # Check for empty or whitespace-only input
    trimmed = raw_input.strip()
    if not trimmed:
        return URLValidationResult(
            is_valid=False,
            raw_input=raw_input,
            error_code="EMPTY_INPUT",
            error_message="URL input cannot be empty or whitespace only."
        )

    # Length boundary check
    if len(trimmed) > max_length:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed[:64] + "...[TRUNCATED]",
            error_code="EXCEEDS_MAX_LENGTH",
            error_message=f"URL length ({len(trimmed)}) exceeds the maximum allowed limit of {max_length} characters."
        )

    # Control character and unprintable byte check
    if CONTROL_CHAR_PATTERN.search(trimmed):
        sanitized, _ = sanitize_credentials_from_url(trimmed)
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized,
            error_code="ILLEGAL_CONTROL_CHARACTERS",
            error_message="URL contains illegal control characters or unprintable bytes."
        )

    # Check for dangerous backslashes in authority or scheme
    authority_part = trimmed.split("?", 1)[0].split("#", 1)[0]
    if "\\" in authority_part:
        sanitized, _ = sanitize_credentials_from_url(trimmed)
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized,
            error_code="MALFORMED_AUTHORITY",
            error_message="URL contains invalid backslash characters in authority or path."
        )

    # Parse URL using urllib.parse.urlsplit
    try:
        parsed = urllib.parse.urlsplit(trimmed)
    except Exception:
        sanitized, _ = sanitize_credentials_from_url(trimmed)
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized,
            error_code="PARSING_FAILED",
            error_message="URL structure could not be parsed."
        )

    # Scheme validation (strict whitelist)
    scheme = parsed.scheme.lower()
    sanitized_url, has_creds = sanitize_credentials_from_url(trimmed)

    if not scheme:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            error_code="MISSING_SCHEME",
            error_message="URL is missing an explicit scheme. Supported schemes are http and https."
        )

    if scheme not in ALLOWED_SCHEMES:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            error_code="UNSUPPORTED_SCHEME",
            error_message=f"Scheme '{scheme}' is not supported. Only http and https are permitted."
        )

    # Detect embedded credentials in valid http/https URLs
    if has_creds:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            has_credentials=True,
            parsed_scheme=scheme,
            error_code="CREDENTIALS_DISALLOWED",
            error_message="Embedded username/password credentials are disallowed for security reasons."
        )

    # Authority / Hostname presence validation
    if not parsed.netloc:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            error_code="MISSING_AUTHORITY",
            error_message="URL is missing a valid network authority (hostname or IP)."
        )

    # Check if parsed.username or parsed.password is populated
    try:
        if parsed.username or parsed.password:
            return URLValidationResult(
                is_valid=False,
                raw_input=trimmed,
                sanitized_input=sanitized_url,
                has_credentials=True,
                parsed_scheme=scheme,
                error_code="CREDENTIALS_DISALLOWED",
                error_message="Embedded username/password credentials are disallowed for security reasons."
            )
    except (ValueError, AttributeError):
        pass

    # Extract hostname safely
    hostname = parsed.hostname
    if not hostname:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            error_code="MISSING_HOSTNAME",
            error_message="URL does not contain a valid hostname."
        )

    # Port validation
    parsed_port: Optional[int] = None
    try:
        parsed_port = parsed.port
    except ValueError as val_err:
        # urlsplit raises ValueError if port is out of range or not digits
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            parsed_hostname=hostname,
            error_code="MALFORMED_PORT",
            error_message="URL port is malformed or not a valid number."
        )

    if parsed_port is not None:
        if parsed_port < 1 or parsed_port > 65535:
            return URLValidationResult(
                is_valid=False,
                raw_input=trimmed,
                sanitized_input=sanitized_url,
                parsed_scheme=scheme,
                parsed_hostname=hostname,
                error_code="PORT_OUT_OF_RANGE",
                error_message=f"Port {parsed_port} is out of permitted range (1-65535)."
            )

    # Hostname syntax validation
    # Allow IPv6 brackets [::1]
    raw_host_str = hostname
    if raw_host_str.startswith("[") and raw_host_str.endswith("]"):
        raw_host_str = raw_host_str[1:-1]

    # Hostname length validation (RFC 1035: max 253 characters)
    if len(raw_host_str) > 253:
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            parsed_hostname=hostname,
            error_code="HOSTNAME_TOO_LONG",
            error_message="Hostname exceeds maximum length of 253 characters."
        )

    # Reject whitespace or prohibited characters in hostname
    if any(c in hostname for c in " \t\r\n<>{}|^`\""):
        return URLValidationResult(
            is_valid=False,
            raw_input=trimmed,
            sanitized_input=sanitized_url,
            parsed_scheme=scheme,
            parsed_hostname=hostname,
            error_code="INVALID_HOSTNAME_CHARACTERS",
            error_message="Hostname contains illegal whitespace or control characters."
        )

    # Hostname labels check (for non-IP domains)
    # Exclude IPv4 or IPv6 from domain label validation
    is_ip = False
    if ":" in raw_host_str or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_host_str):
        is_ip = True

    if not is_ip:
        labels = raw_host_str.rstrip(".").split(".")
        for label in labels:
            if not label:
                return URLValidationResult(
                    is_valid=False,
                    raw_input=trimmed,
                    sanitized_input=sanitized_url,
                    parsed_scheme=scheme,
                    parsed_hostname=hostname,
                    error_code="EMPTY_DOMAIN_LABEL",
                    error_message="Domain contains empty label (consecutive dots)."
                )
            if len(label) > 63:
                return URLValidationResult(
                    is_valid=False,
                    raw_input=trimmed,
                    sanitized_input=sanitized_url,
                    parsed_scheme=scheme,
                    parsed_hostname=hostname,
                    error_code="DOMAIN_LABEL_TOO_LONG",
                    error_message=f"Domain label '{label[:15]}...' exceeds 63 characters."
                )
            if label.startswith("-") or label.endswith("-"):
                return URLValidationResult(
                    is_valid=False,
                    raw_input=trimmed,
                    sanitized_input=sanitized_url,
                    parsed_scheme=scheme,
                    parsed_hostname=hostname,
                    error_code="INVALID_LABEL_HYPHEN",
                    error_message="Domain label cannot start or end with a hyphen."
                )

    # Input successfully passed all Part 05 validation checks
    return URLValidationResult(
        is_valid=True,
        raw_input=trimmed,
        sanitized_input=sanitized_url,
        parsed_scheme=scheme,
        parsed_hostname=hostname,
        parsed_port=parsed_port,
        has_credentials=False
    )
