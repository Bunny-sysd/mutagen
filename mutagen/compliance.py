COMPLIANCE_MAP = {
    "CWE-120": {
        "PCI-DSS": "Requirement 6.2.4 (Buffer overflow prevention)",
        "SOC2": "CC7.1, CC7.2 (Vulnerability management & mitigation)"
    },
    "CWE-134": {
        "PCI-DSS": "Requirement 6.2.4 (Format string vulnerability prevention)",
        "SOC2": "CC7.1 (Input validation controls)"
    },
    "CWE-843": {
        "PCI-DSS": "Requirement 6.2.4 (Type confusion & memory safety controls)",
        "SOC2": "CC7.1, CC7.2 (Secure system design)"
    }
}

def map_cwe_to_compliance(cwe_id: str) -> dict:
    """Map a CWE ID to compliance standard requirements (PCI-DSS, SOC2)."""
    cwe_clean = cwe_id.upper().strip()
    return COMPLIANCE_MAP.get(cwe_clean, {
        "PCI-DSS": "Requirement 6.2.4 (General secure application development)",
        "SOC2": "CC7.1 (System boundaries validation)"
    })
