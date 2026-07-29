"""
Dynamic Compliance Standard Mapping Engine.
Maps any CWE ID or vulnerability type to relevant PCI-DSS, SOC2, OWASP, and NIST controls.
"""


def map_cwe_to_compliance(cwe_id: str) -> dict[str, str]:
    """Dynamically map any CWE ID to security standards and compliance frameworks."""
    cwe_clean = (cwe_id or "").upper().strip()
    cwe_num = "".join(filter(str.isdigit, cwe_clean))

    # Basic category dynamic inference based on CWE ranges & common patterns
    num = int(cwe_num) if cwe_num else 0

    if num in (120, 121, 122, 131, 787, 125, 119):
        category = "Memory Safety & Buffer Protection"
        owasp = "A06:2021 - Vulnerable and Outdated Components / Memory Safety"
        pci = "Requirement 6.2.4 (Buffer overflow & memory protection)"
        soc2 = "CC7.1, CC7.2 (Vulnerability management & buffer safety controls)"
    elif num in (134, 89, 78, 77, 94):
        category = "Input Validation & Injection Prevention"
        owasp = "A03:2021 - Injection"
        pci = "Requirement 6.2.4 (Sanitization & injection prevention)"
        soc2 = "CC7.1 (Input validation & boundary integrity)"
    elif num in (416, 415, 401, 476):
        category = "Memory Lifecycle & Pointer Safety"
        owasp = "A06:2021 - Memory Management & Resource Safety"
        pci = "Requirement 6.2.4 (Resource management & safe pointers)"
        soc2 = "CC7.2 (System integrity & memory management)"
    elif num in (190, 191, 681):
        category = "Numeric & Arithmetic Safety"
        owasp = "A04:2021 - Insecure Design"
        pci = "Requirement 6.2.4 (Arithmetic overflow prevention)"
        soc2 = "CC7.1 (System logic & validation controls)"
    elif num in (843, 704):
        category = "Type Safety & Object Casting"
        owasp = "A04:2021 - Insecure Design"
        pci = "Requirement 6.2.4 (Type safety & memory isolation)"
        soc2 = "CC7.1, CC7.2 (Secure system design & type boundaries)"
    else:
        category = f"General Security Control ({cwe_clean if cwe_clean else 'CWE-General'})"
        owasp = "A04:2021 - Insecure Design"
        pci = "Requirement 6.2.4 (General secure application development)"
        soc2 = "CC7.1 (System boundaries & input validation)"

    return {
        "Category": category,
        "OWASP": owasp,
        "PCI-DSS": pci,
        "SOC2": soc2,
        "NIST-800-53": "SI-16 (Memory Protection & Input Sanitization)",
    }

