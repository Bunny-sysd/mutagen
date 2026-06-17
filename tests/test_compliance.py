from mutagen.compliance import map_cwe_to_compliance

def test_cwe_compliance_mapping():
    mapping = map_cwe_to_compliance("CWE-120")
    assert "PCI-DSS" in mapping
    assert "SOC2" in mapping
    assert "Requirement 6" in mapping["PCI-DSS"]

def test_cwe_compliance_unknown():
    mapping = map_cwe_to_compliance("CWE-999")
    assert "PCI-DSS" in mapping
    assert "SOC2" in mapping
    assert "Requirement 6" in mapping["PCI-DSS"]
