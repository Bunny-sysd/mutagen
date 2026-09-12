"""
Unit tests for Mutagen Intelligence and Binary Repair Engines.
"""

import json
from unittest.mock import MagicMock, patch

from mutagen.binary_repair import MAGIC_ELF, MAGIC_PNG, repair_binary_payload
from mutagen.intelligence import VulnerabilityIntelligenceEngine


def test_token_efficient_intelligence():
    engine = VulnerabilityIntelligenceEngine()
    intel = engine.get_refined_intelligence("CWE-190", "Integer Overflow")
    assert intel["token_optimized"] is True
    assert intel["selected_cwe"] == "CWE-190"
    assert intel["cvss_score"] >= 7.0
    assert "signature_hint" in intel


def _mock_github_response(mock_urlopen, items):
    mock_cm = MagicMock()
    mock_cm.status = 200
    mock_cm.read.return_value = json.dumps({"items": items}).encode("utf-8")
    mock_cm.__enter__.return_value = mock_cm
    mock_urlopen.return_value = mock_cm


@patch("urllib.request.urlopen")
def test_get_refined_intelligence_prefers_live_github_poc(mock_urlopen):
    """When a real GitHub PoC repo is found, its details must drive the
    signature_hint instead of the generic offline-template text."""
    _mock_github_response(mock_urlopen, [{
        "full_name": "someuser/cve-2024-fake-poc",
        "html_url": "https://github.com/someuser/cve-2024-fake-poc",
        "description": "Working exploit for the fake overflow",
        "stargazers_count": 42,
    }])

    engine = VulnerabilityIntelligenceEngine()
    intel = engine.get_refined_intelligence("CWE-120", "Buffer Overflow")

    assert intel["selected_cwe"] == "CWE-120"
    assert "someuser/cve-2024-fake-poc" in intel["signature_hint"]
    assert "https://github.com/someuser/cve-2024-fake-poc" in intel["signature_hint"]
    # Severity/CVSS for a known CWE still come from the offline table --
    # GitHub search results carry no severity data of their own.
    assert intel["severity"] == "HIGH"
    assert intel["cvss_score"] == 7.8


@patch("urllib.request.urlopen")
def test_get_refined_intelligence_falls_back_offline_when_live_search_empty(mock_urlopen):
    """When the live GitHub search returns no real hits (or fails), behavior
    must be identical to the pre-existing pure-offline lookup."""
    _mock_github_response(mock_urlopen, [])  # zero real results

    engine = VulnerabilityIntelligenceEngine()
    intel = engine.get_refined_intelligence("CWE-190", "Integer Overflow")

    assert intel["token_optimized"] is True
    assert intel["selected_cwe"] == "CWE-190"
    assert intel["cvss_score"] >= 7.0
    assert "signature_hint" in intel
    assert "github" not in intel["signature_hint"].lower()


@patch("urllib.request.urlopen", side_effect=OSError("network unreachable"))
def test_get_refined_intelligence_falls_back_offline_when_live_search_errors(mock_urlopen):
    """A network error during the live lookup must never propagate -- it
    must silently fall back to the offline signature dictionary."""
    engine = VulnerabilityIntelligenceEngine()
    intel = engine.get_refined_intelligence("CWE-78", "OS Command Injection")

    assert intel["selected_cwe"] == "CWE-78"
    assert intel["severity"] == "CRITICAL"
    assert "signature_hint" in intel


def test_png_binary_repair():
    # Minimal 8-byte PNG header + dummy IHDR chunk with un-recalculated CRC
    dummy_png = MAGIC_PNG + b"\x00\x00\x00\x0dIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00\x00\x00\x00\x00"
    repaired = repair_binary_payload(dummy_png)
    assert isinstance(repaired, bytes)
    assert repaired.startswith(MAGIC_PNG)
    assert len(repaired) >= len(dummy_png)


def test_elf_header_repair():
    # Corrupted 16-byte ELF header
    corrupted_elf = b"\x00\x00\x00\x00" + b"\x00" * 12
    repaired = repair_binary_payload(corrupted_elf, target_hint="target.elf")
    assert repaired.startswith(MAGIC_ELF)
    assert repaired[4] in (1, 2)  # EI_CLASS (32/64-bit)


def test_text_payload_passthrough():
    text_payload = "; id; echo PWNED"
    repaired = repair_binary_payload(text_payload)
    assert repaired == text_payload.encode("utf-8")
