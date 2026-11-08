"""CyberShield AI — Part 06: URL Normalization

Implements canonical URL normalization conforming to RFC 3986 and RFC 5891.
Normalizes scheme and host casing, resolves IDN/Punycode representations, removes
default ports, removes RFC 3986 dot-segments without collapsing repeated slashes,
normalizes unreserved percent-encodings, and extracts registrable domains using
Public Suffix List (PSL) rules without guessing on unknown suffixes.
"""

import re
import urllib.parse
from typing import Optional, Set
import idna

from app.schemas.url_scan import URLNormalizationResult
from app.services.url_investigation.validation import validate_url_input

# =============================================================================
# Public Suffix List (PSL) Recognized Suffixes
# Includes ICANN generic & country-code TLDs, multi-part ccTLDs, and major
# private/cloud shared hosting public suffixes (e.g. *.github.io, *.pages.dev)
# =============================================================================

RECOGNIZED_PUBLIC_SUFFIXES: Set[str] = {
    # Private / Cloud / Shared Hosting Public Suffixes (Mozilla PSL Private Domains)
    "github.io",
    "pages.dev",
    "workers.dev",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "cloudapp.net",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "gitlab.io",
    "fastlylb.net",
    "myshopify.com",
    "cloudfront.net",
    "elasticbeanstalk.com",

    # Common Multi-Part Country-Code Top-Level Domains (ccTLDs)
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "net.uk", "sch.uk", "police.uk", "plc.uk",
    "co.in", "net.in", "org.in", "gen.in", "ind.in", "firm.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "gen.nz", "kiwi.nz", "maori.nz", "mil.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ed.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "ind.br", "esp.br", "inf.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "mil.cn",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "edu.za", "law.za", "mil.za",
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
    "co.il", "net.il", "org.il", "gov.il", "ac.il", "muni.il", "k12.il", "idf.il",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "k12.tr",
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    "co.id", "net.id", "org.id", "go.id", "ac.id", "sch.id", "web.id", "my.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my", "mil.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "co.th", "in.th", "net.th", "org.th", "go.th", "ac.th", "mi.th",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "gc.ca", "qc.ca", "on.ca", "bc.ca", "ab.ca",

    # Standard Generic Top-Level Domains (gTLDs) & ccTLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "aero", "coop", "museum",
    "io", "ai", "co", "me", "cc", "tv", "app", "dev", "cloud", "tech", "online", "store", "site", "website",
    "space", "live", "world", "today", "agency", "global", "center", "digital", "zone", "network", "solutions",
    "expert", "group", "services", "support", "systems", "security", "email", "chat", "link", "click", "press",
    "news", "media", "social", "xyz", "top", "icu", "club", "vip", "shop", "work", "fun", "bar", "pub", "one",
    "us", "uk", "de", "fr", "it", "es", "nl", "ca", "in", "au", "jp", "cn", "ru", "br", "za", "se", "no",
    "dk", "fi", "ch", "at", "be", "pl", "cz", "ie", "nz", "sg", "hk", "kr", "mx", "il", "tr", "tw", "ar",
    "cl", "id", "my", "ph", "th", "vn", "ng", "ke", "eg", "sa", "ae", "eu", "su", "ua", "ro", "gr", "pt",
    "ly", "gd",
}

# RFC 3986 Unreserved characters percent-encoding map (ASCII: A-Z, a-z, 0-9, -, ., _, ~)
UNRESERVED_HEX_TO_CHAR = {}
for i in range(256):
    c = chr(i)
    if c.isalnum() or c in "-._~":
        UNRESERVED_HEX_TO_CHAR[f"%{i:02x}"] = c
        UNRESERVED_HEX_TO_CHAR[f"%{i:02X}"] = c


def extract_registrable_domain(hostname: str) -> Optional[str]:
    """Extract the registrable domain (eTLD+1) using Public Suffix List rules.
    
    Identifies the longest matching public suffix (including multi-part ccTLDs and
    major cloud/serverless hosting suffixes like *.github.io, *.pages.dev, *.workers.dev).
    
    If the domain suffix is unknown or unsupported, returns None rather than guessing
    with the last two labels, ensuring uncertain domain extraction cannot be silently
    trusted in threat intelligence or security evaluation.
    
    Args:
        hostname: Clean hostname string.
        
    Returns:
        Registrable domain (e.g. 'phishing-tenant.github.io', 'example.co.uk', 'example.com')
        or None if hostname is an IP, bare suffix, or has an unknown public suffix.
    """
    if not hostname or ":" in hostname or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return None  # IP address has no registrable domain

    clean_host = hostname.rstrip(".").lower()
    labels = clean_host.split(".")
    if len(labels) <= 1:
        return None

    # Search for the longest matching public suffix
    matched_suffix = None
    suffix_label_count = 0
    for count in range(len(labels), 0, -1):
        candidate = ".".join(labels[-count:])
        if candidate in RECOGNIZED_PUBLIC_SUFFIXES:
            matched_suffix = candidate
            suffix_label_count = count
            break

    # If no recognized public suffix matched, do NOT guess using last two labels!
    if not matched_suffix:
        return None

    # If the hostname is exactly the public suffix with no tenant/domain prefix
    # (e.g. 'github.io', 'co.uk', 'com'), it is a bare suffix, not a registrable domain.
    if len(labels) <= suffix_label_count:
        return None

    # eTLD+1 is the label immediately preceding the suffix plus the suffix
    registrable_label = labels[-suffix_label_count - 1]
    return f"{registrable_label}.{matched_suffix}"


def remove_dot_segments(path: str) -> str:
    """Implement RFC 3986 Section 5.2.4 Remove Dot Segments algorithm.
    
    Safely resolves '.' and '..' dot segments WITHOUT collapsing repeated slashes,
    thereby preserving the exact path structure required for signature verification,
    HMAC validation, API routing, and server access-control behavior.
    """
    if not path:
        return "/"

    input_buf = path
    output_buf = []

    while input_buf:
        # Step 2.A: If the input buffer begins with a prefix of "../" or "./",
        # then remove that prefix from the input buffer.
        if input_buf.startswith("../"):
            input_buf = input_buf[3:]
        elif input_buf.startswith("./"):
            input_buf = input_buf[2:]
        # Step 2.B: if input buffer begins with a prefix of "/./" or "/.",
        # replace that prefix with "/"
        elif input_buf.startswith("/./"):
            input_buf = "/" + input_buf[3:]
        elif input_buf == "/.":
            input_buf = "/"
        # Step 2.C: if input buffer begins with a prefix of "/../" or "/..",
        # replace that prefix with "/" and pop the last segment and its preceding "/"
        elif input_buf.startswith("/../"):
            input_buf = "/" + input_buf[4:]
            if output_buf:
                output_buf.pop()
        elif input_buf == "/..":
            input_buf = "/"
            if output_buf:
                output_buf.pop()
        # Step 2.D: if input buffer consists only of "." or "..", remove that
        elif input_buf in (".", ".."):
            input_buf = ""
        # Step 2.E: move the first path segment in the input buffer to the output buffer
        else:
            if input_buf.startswith("/"):
                next_slash = input_buf.find("/", 1)
            else:
                next_slash = input_buf.find("/", 0)

            if next_slash == -1:
                seg = input_buf
                input_buf = ""
            else:
                seg = input_buf[:next_slash]
                input_buf = input_buf[next_slash:]

            output_buf.append(seg)

    resolved = "".join(output_buf)
    return resolved if resolved else "/"


def normalize_percent_encoding(path_or_query: str) -> str:
    """Normalize percent-encoding according to RFC 3986.
    
    - Decodes unreserved characters (letters, digits, '-', '.', '_', '~').
    - Uppercases hex digits for remaining percent-encoded bytes.
    - Avoids double-decoding or altering reserved delimiters.
    """
    if not path_or_query:
        return path_or_query

    # Replace unreserved percent-encodings with literal characters
    def replace_unreserved(match):
        code = match.group(0)
        return UNRESERVED_HEX_TO_CHAR.get(code, code.upper())

    return re.sub(r"%[0-9a-fA-F]{2}", replace_unreserved, path_or_query)


def normalize_url(raw_url: str) -> URLNormalizationResult:
    """Normalize a validated URL into a consistent canonical representation.
    
    Preserves repeated slashes in the path so that request semantics and signed
    URLs (HMAC) are not broken. Provides a separate display_path for UI display.
    
    Args:
        raw_url: Input URL string.
        
    Returns:
        URLNormalizationResult with canonical URL, preserved path, and PSL registrable domain.
        
    Raises:
        ValueError: If raw_url fails Part 05 intake validation.
    """
    validation = validate_url_input(raw_url)
    if not validation.is_valid:
        raise ValueError(f"Cannot normalize invalid URL: {validation.error_message} (Code: {validation.error_code})")

    parsed = urllib.parse.urlsplit(validation.raw_input)

    # 1. Normalize Scheme
    scheme = parsed.scheme.lower()

    # 2. Normalize Hostname & Internationalized Domain Names (IDN)
    raw_host = parsed.hostname.rstrip(".")
    is_idn = False
    unicode_host: Optional[str] = None
    punycode_host: Optional[str] = None

    # Determine if IPv6 bracketed host
    is_ipv6 = raw_host.startswith("[") and raw_host.endswith("]") or ":" in raw_host

    if is_ipv6:
        canonical_host = raw_host.lower()
        punycode_host = canonical_host
        unicode_host = canonical_host
    else:
        try:
            if any(ord(c) > 127 for c in raw_host):
                is_idn = True
                punycode_host = idna.encode(raw_host).decode("ascii").lower()
                unicode_host = idna.decode(punycode_host)
                canonical_host = punycode_host
            elif "xn--" in raw_host.lower():
                is_idn = True
                punycode_host = raw_host.lower()
                try:
                    unicode_host = idna.decode(punycode_host)
                except Exception:
                    unicode_host = punycode_host
                canonical_host = punycode_host
            else:
                canonical_host = raw_host.lower()
                punycode_host = canonical_host
                unicode_host = canonical_host
        except Exception:
            canonical_host = raw_host.lower()
            punycode_host = canonical_host
            unicode_host = canonical_host

    # 3. Normalize Port (omit default 80 for http, 443 for https)
    port = validation.parsed_port
    explicit_port: Optional[int] = None
    if port is not None:
        if scheme == "http" and port == 80:
            explicit_port = None
        elif scheme == "https" and port == 443:
            explicit_port = None
        else:
            explicit_port = port

    # 4. Normalize Path (strictly preserving consecutive slashes for request semantics)
    raw_path = parsed.path
    if not raw_path:
        norm_path = "/"
        display_path = "/"
    else:
        dot_resolved = remove_dot_segments(raw_path)
        norm_path = normalize_percent_encoding(dot_resolved)
        # Separate display-normalized representation for human UI only
        display_path = re.sub(r"/+", "/", norm_path)

    # 5. Normalize Query and Fragment
    norm_query: Optional[str] = None
    if parsed.query:
        norm_query = normalize_percent_encoding(parsed.query)

    fragment: Optional[str] = parsed.fragment if parsed.fragment else None

    # 6. Registrable Domain Extraction (PSL rules, no guessing)
    reg_domain = extract_registrable_domain(canonical_host)

    # 7. Construct Canonical Normalized URL (preserves exact path slashes)
    if is_ipv6 and not canonical_host.startswith("["):
        authority = f"[{canonical_host}]"
    else:
        authority = canonical_host

    if explicit_port is not None:
        authority += f":{explicit_port}"

    canonical_url = f"{scheme}://{authority}{norm_path}"
    if norm_query:
        canonical_url += f"?{norm_query}"

    return URLNormalizationResult(
        original_url=validation.raw_input,
        normalized_url=canonical_url,
        scheme=scheme,
        hostname=canonical_host,
        unicode_hostname=unicode_host,
        punycode_hostname=punycode_host,
        is_idn=is_idn,
        port=explicit_port,
        path=norm_path,
        display_path=display_path,
        query=norm_query,
        fragment=fragment,
        registrable_domain=reg_domain
    )
