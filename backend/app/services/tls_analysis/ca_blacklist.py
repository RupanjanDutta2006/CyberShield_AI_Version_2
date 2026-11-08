"""CyberShield AI — Compromised & Distrusted Certificate Authority (CA) Registry

Curated intelligence dataset of historical and active untrusted, compromised,
or rogue intermediate CAs (e.g. eMudhra sub-CA incidents, DigiNotar, WoSign/StartCom,
and unauthorized MITM subordinate CAs).
"""

from typing import Dict, Any, Optional, List

# Curated historical CA compromise and distrust records
KNOWN_COMPROMISED_CAS: List[Dict[str, Any]] = [
    {
        "id": "EMUDHRA_SUB_CA_UNAUTHORIZED_2014",
        "name": "eMudhra Consumer / Sub-CA Unauthorized Issuance",
        "keywords": ["emudhra", "e-mudhra"],
        "compromise_type": "Unauthorized Domain Certificate Issuance",
        "severity": "CRITICAL",
        "description": (
            "Historical incident: In 2014, an authorized subordinate CA under eMudhra / India CCA "
            "issued unauthorized X.509 wildcards for high-profile domains (Google, Yahoo) without domain "
            "control validation, leading to browser vendor distrust of affected intermediate serials."
        ),
        "remediation": "Do not trust intermediate certificates signed by distrusted eMudhra sub-CA branches."
    },
    {
        "id": "DIGINOTAR_ROOT_BREACH_2011",
        "name": "DigiNotar Compromised Root & Intermediate CAs",
        "keywords": ["diginotar"],
        "compromise_type": "Complete Root CA Private Key Compromise",
        "severity": "CRITICAL",
        "description": (
            "Catastrophic 2011 intrusion where attackers obtained unauthorized wildcard certificates for *.google.com "
            "and hundreds of high-value domains, resulting in universal root removal across all major operating systems."
        ),
        "remediation": "Immediately revoke and replace certificates issued by any DigiNotar lineage."
    },
    {
        "id": "WOSIGN_STARTCOM_DISTRUST_2016",
        "name": "WoSign & StartCom Backdating and Operational Distrust",
        "keywords": ["wosign", "startcom", "startssl"],
        "compromise_type": "Intentional Backdating and Free Certificate Mis-issuance",
        "severity": "HIGH",
        "description": (
            "Mozilla, Apple, and Google permanently distrusted WoSign and StartCom in 2016 following documented "
            "backdating of SHA-1 certificates and failure to validate domain control on multi-tenant infrastructure."
        ),
        "remediation": "Migrate to modern automated CAs (Let's Encrypt, DigiCert, Sectigo, Google Trust Services)."
    },
    {
        "id": "CNNIC_MCS_HOLDINGS_MITM_2015",
        "name": "CNNIC / MCS Holdings Unauthorized Intermediates",
        "keywords": ["mcsholdings", "mcs holdings"],
        "compromise_type": "Unauthorized Subordinate CA for MITM Proxy",
        "severity": "HIGH",
        "description": (
            "In 2015, an intermediate CA delegated by CNNIC to MCS Holdings was improperly configured inside a "
            "firewall proxy, issuing fraudulent certificates for domains outside its administrative boundary."
        ),
        "remediation": "Reject certificates chaining to unconstrained private intermediate CAs."
    },
    {
        "id": "FINFISHER_DARK_CARACAL_MALWARE_CA",
        "name": "FinFisher / Commercial Spyware Rogue CA",
        "keywords": ["finfisher", "dark caracal", "cyber espionage ca"],
        "compromise_type": "Malware & Surveillance CAs",
        "severity": "CRITICAL",
        "description": (
            "Rogue local or sub-CA root certificates deployed by surveillance frameworks to conduct unauthorized "
            "TLS decryption and interception of civilian traffic."
        ),
        "remediation": "Flag as severe surveillance artifact and block all associated connections."
    }
]


def check_ca_compromise(issuer_dict: Dict[str, str], serial_number: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Check certificate issuer attributes against known compromised CA incident registry.
    
    Returns:
        Incident dictionary if match is found, otherwise None.
    """
    if not issuer_dict:
        return None

    # Search CN, O, OU fields
    issuer_text = " ".join([
        issuer_dict.get("commonName", ""),
        issuer_dict.get("organizationName", ""),
        issuer_dict.get("organizationalUnitName", "")
    ]).lower()

    for incident in KNOWN_COMPROMISED_CAS:
        for kw in incident["keywords"]:
            if kw in issuer_text:
                return {
                    "incident_id": incident["id"],
                    "incident_name": incident["name"],
                    "severity": incident["severity"],
                    "compromise_type": incident["compromise_type"],
                    "description": incident["description"],
                    "remediation": incident["remediation"],
                    "matched_keyword": kw,
                    "issuer_name": issuer_dict.get("commonName") or issuer_dict.get("organizationName", "Unknown")
                }

    return None

