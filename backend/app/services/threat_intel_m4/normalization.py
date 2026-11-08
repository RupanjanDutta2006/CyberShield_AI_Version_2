import ipaddress
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


DANGEROUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "rest", "buzz", "country",
    "gq", "cf", "ml", "work", "fit", "surf", "cfd", "sbs"
}


class URLNormalizer:
    """
    Validates, parses, normalizes, and safely handles URLs without opening or crawling them.
    Treats all incoming target inputs as untrusted.
    """

    @staticmethod
    def sanitize_input(raw_target: str) -> str:
        """Strip whitespace, control characters, and leading/trailing quotes."""
        if not raw_target:
            raise ValueError("Target input cannot be empty.")
        clean = raw_target.strip().strip("'\"`")
        if len(clean) > 2048:
            raise ValueError("Target input exceeds maximum permissible length (2048 chars).")
        return clean

    @staticmethod
    def defang_url(url: str) -> str:
        """
        Produces a defanged version of a URL safe for display in cybersecurity dashboards:
        e.g., https://malicious.com -> hxxps://malicious[.]com
        """
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        # Defang dots in hostname before path
        if "/" in defanged[8:]:
            prefix, rest = defanged.split("/", 3)[0:3], "/".join(defanged.split("/")[3:])
            host_part = "/".join(prefix)
            host_part = re.sub(r'\.(?=[a-zA-Z0-9])', '[.]', host_part)
            return f"{host_part}/{rest}"
        else:
            return re.sub(r'\.(?=[a-zA-Z0-9])', '[.]', defanged)

    @classmethod
    def normalize_target(cls, raw_target: str) -> Dict[str, Optional[str]]:
        """
        Validates target format and extracts hostname, domain, and normalized URL.
        Does not execute DNS requests or open connections.
        """
        sanitized = cls.sanitize_input(raw_target)

        # Detect scheme
        if not (sanitized.startswith("http://") or sanitized.startswith("https://")):
            # If target looks like domain or host/path, default to https://
            candidate_url = f"https://{sanitized}"
        else:
            candidate_url = sanitized

        try:
            parsed = urlparse(candidate_url)
        except Exception as e:
            raise ValueError(f"Invalid URL structure: {e}")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("Target does not contain a valid host or domain name.")

        # Check for invalid characters in host
        if any(c in hostname for c in ["<", ">", "\"", " ", "\t", "\r", "\n", ";", "{", "}"]):
            raise ValueError("Hostname contains invalid characters or illegal syntax.")

        # Identify IP literal
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        # Extract registrable domain (simplified eTLD+1 extraction)
        domain = hostname
        tld = ""
        if not is_ip:
            parts = hostname.split(".")
            if len(parts) >= 2:
                # Handle multi-part suffixes like .co.uk, .gov.in
                if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "gov", "edu", "net", "ac"]:
                    domain = ".".join(parts[-3:])
                    tld = parts[-1]
                else:
                    domain = ".".join(parts[-2:])
                    tld = parts[-1]
            else:
                domain = hostname
                tld = ""

        # Reconstruct normalized URL with safe path
        normalized_url = f"{parsed.scheme}://{hostname}"
        if parsed.port and parsed.port not in [80, 443]:
            normalized_url += f":{parsed.port}"
        normalized_url += parsed.path or "/"
        if parsed.query:
            normalized_url += f"?{parsed.query}"

        return {
            "original": sanitized,
            "normalized_url": normalized_url,
            "hostname": hostname,
            "domain": domain,
            "tld": tld,
            "is_ip_literal": is_ip,
            "defanged_url": cls.defang_url(normalized_url),
            "scheme": parsed.scheme,
            "port": parsed.port
        }
