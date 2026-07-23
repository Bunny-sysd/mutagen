import pytest


@pytest.fixture
def sample_crash_data():
    return {
        "args": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        "vuln_type": "Buffer Overflow",
        "cwe": "CWE-120",
        "severity": "critical",
        "reason": "Vulnerability triggered due to unchecked strcpy buffer copy.",
        "crash_type": "ACCESS_VIOLATION",
        "return_code": -1073741819
    }
