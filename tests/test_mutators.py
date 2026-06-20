"""Tests for the traditional mutation fallback engine."""

import pytest
from mutagen.mutators import (
    generate_fallback_payloads,
    _buffer_overflow_payloads,
    _format_string_payloads,
    _integer_boundary_payloads,
    _null_and_special_payloads,
    _command_injection_payloads,
    _off_by_one_payloads,
)


# ---------------------------------------------------------------------------
# Individual strategy tests
# ---------------------------------------------------------------------------

class TestBufferOverflowPayloads:
    def test_generates_multiple_payloads(self):
        payloads = _buffer_overflow_payloads("args")
        assert len(payloads) >= 4

    def test_escalating_lengths(self):
        payloads = _buffer_overflow_payloads("args")
        lengths = [len(p["args"][0]) for p in payloads]
        assert lengths == sorted(lengths), "Buffer lengths should escalate"

    def test_correct_vuln_type(self):
        for p in _buffer_overflow_payloads("args"):
            assert p["vuln_type"] == "buffer_overflow"
            assert p["cwe"] == "CWE-120"

    def test_stdin_mode_uses_input_data(self):
        payloads = _buffer_overflow_payloads("stdin")
        for p in payloads:
            assert p["args"] == []
            assert len(p["input_data"]) > 0


class TestFormatStringPayloads:
    def test_generates_payloads(self):
        payloads = _format_string_payloads("args")
        assert len(payloads) >= 3

    def test_contains_format_specifiers(self):
        for p in _format_string_payloads("args"):
            data = p["args"][0]
            assert any(spec in data for spec in ["%s", "%x", "%n", "%p", "%08x"]), \
                f"Expected format specifier in: {data}"

    def test_correct_metadata(self):
        for p in _format_string_payloads("args"):
            assert p["vuln_type"] == "format_string"
            assert p["cwe"] == "CWE-134"
            assert p["severity"] == "critical"


class TestIntegerBoundaryPayloads:
    def test_generates_payloads(self):
        payloads = _integer_boundary_payloads("args")
        assert len(payloads) >= 5

    def test_includes_critical_boundaries(self):
        values = [p["args"][0] for p in _integer_boundary_payloads("args")]
        assert "0" in values
        assert "-1" in values
        assert "2147483647" in values  # INT32_MAX
        assert "-2147483648" in values  # INT32_MIN

    def test_correct_metadata(self):
        for p in _integer_boundary_payloads("args"):
            assert p["vuln_type"] == "integer_overflow"
            assert p["cwe"] == "CWE-190"


class TestNullAndSpecialPayloads:
    def test_generates_payloads(self):
        payloads = _null_and_special_payloads("args")
        assert len(payloads) >= 3

    def test_includes_empty_string(self):
        inputs = [p["input_data"] for p in _null_and_special_payloads("args")]
        assert "" in inputs

    def test_includes_null_bytes(self):
        inputs = [p["input_data"] for p in _null_and_special_payloads("args")]
        assert any("\x00" in v for v in inputs)


class TestCommandInjectionPayloads:
    def test_generates_payloads(self):
        payloads = _command_injection_payloads("args")
        assert len(payloads) >= 3

    def test_includes_shell_metacharacters(self):
        values = [p["args"][0] for p in _command_injection_payloads("args")]
        metacharacters = [";", "|", "$", "`", "&&", "||"]
        found = [any(mc in v for v in values) for mc in metacharacters]
        assert sum(found) >= 4, "Should include multiple shell metacharacter patterns"


class TestOffByOnePayloads:
    def test_generates_payloads(self):
        payloads = _off_by_one_payloads("args")
        assert len(payloads) >= 10

    def test_boundary_adjacent_lengths(self):
        """For each boundary, we should see length-1, length, and length+1."""
        lengths = sorted(len(p["args"][0]) for p in _off_by_one_payloads("args"))
        # Check that 15, 16, 17 all appear (boundary=16)
        assert 15 in lengths
        assert 16 in lengths
        assert 17 in lengths


# ---------------------------------------------------------------------------
# Integration: generate_fallback_payloads()
# ---------------------------------------------------------------------------

class TestGenerateFallbackPayloads:
    def test_returns_requested_count(self):
        payloads = generate_fallback_payloads(max_payloads=10, delivery_mode="args")
        assert len(payloads) <= 10

    def test_diverse_vuln_types(self):
        """Should include payloads from multiple strategy categories."""
        payloads = generate_fallback_payloads(max_payloads=20, delivery_mode="args")
        vuln_types = set(p["vuln_type"] for p in payloads)
        # At least 4 of the 6 categories should appear
        assert len(vuln_types) >= 4, f"Only got vuln types: {vuln_types}"

    def test_all_payloads_have_required_fields(self):
        required = {"args", "input_data", "vuln_type", "reason", "severity", "cwe"}
        for p in generate_fallback_payloads(max_payloads=15, delivery_mode="args"):
            assert required.issubset(p.keys()), f"Missing fields: {required - p.keys()}"

    def test_args_mode_populates_args(self):
        for p in generate_fallback_payloads(max_payloads=10, delivery_mode="args"):
            assert isinstance(p["args"], list)

    def test_stdin_mode_populates_input_data(self):
        for p in generate_fallback_payloads(max_payloads=10, delivery_mode="stdin"):
            assert p["args"] == []
            # input_data can be empty string for the "empty string" test case
            assert isinstance(p["input_data"], str)

    def test_small_budget_still_diverse(self):
        """Even with a tiny budget, we get at least one from each category."""
        payloads = generate_fallback_payloads(max_payloads=6, delivery_mode="args")
        vuln_types = set(p["vuln_type"] for p in payloads)
        assert len(vuln_types) == 6, f"With budget=6, expected 6 types but got: {vuln_types}"

    def test_zero_budget_returns_empty(self):
        payloads = generate_fallback_payloads(max_payloads=0, delivery_mode="args")
        assert payloads == []
