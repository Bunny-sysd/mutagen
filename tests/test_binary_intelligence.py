"""
Unit tests for Mutagen Intelligence and Binary Repair Engines.
"""

from mutagen.binary_repair import MAGIC_ELF, MAGIC_PNG, repair_binary_payload
from mutagen.intelligence import VulnerabilityIntelligenceEngine


def test_token_efficient_intelligence():
    engine = VulnerabilityIntelligenceEngine()
    intel = engine.get_refined_intelligence("CWE-190", "Integer Overflow")
    assert intel["token_optimized"] is True
    assert intel["selected_cwe"] == "CWE-190"
    assert intel["cvss_score"] >= 7.0
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
