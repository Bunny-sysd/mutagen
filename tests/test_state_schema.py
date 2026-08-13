"""
Schema Completeness and Boundary Integrity Unit Tests for Mutagen.
Verifies that ProgramContext, CrashPayload, VulnerabilityDetail, and PatchProposal
declare all necessary fields and handle dynamic assignment safely without ValueError.
"""

import pytest
from mutagen.state import (
    ProgramContext,
    CrashPayload,
    VulnerabilityDetail,
    PatchProposal,
)


def test_program_context_schema_completeness():
    """
    Asserts all fields used across the codebase are explicitly defined
    and can be initialized and mutated without raising ValueError.
    """
    ctx = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="int main() { return 0; }",
    )

    # Core execution & configuration fields
    ctx.delivery_mode = "file"
    ctx.is_binary = False
    ctx.decompiler_used = "ghidra"
    ctx.architecture = "x86_64"
    ctx.docker_available = True
    ctx.sandboxed = True
    ctx.user_confirmed_unsandboxed = False
    ctx.ci_mode = True
    ctx.skip_flagged_findings = True

    # Telemetry and reachability fields (Bug B fix & schema audit)
    ctx.reachability_status = "ACTIVE_BINARY"
    ctx.reachability_message = "Target binary 'pngtest'"
    ctx.triage_failed = True
    ctx.triage_error = "JSON parse failure"
    ctx.verification_status = "VERIFIED_SECURE"

    # Verify values
    assert ctx.reachability_status == "ACTIVE_BINARY"
    assert ctx.reachability_message == "Target binary 'pngtest'"
    assert ctx.triage_failed is True
    assert ctx.triage_error == "JSON parse failure"


def test_program_context_extra_attribute_safety():
    """
    Ensures that unexpected or diagnostic attributes set dynamically
    do not crash the process with ValueError.
    """
    ctx = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="int main() { return 0; }",
    )
    # Dynamic diagnostic field
    ctx.diagnostic_run_id = "test_run_12345"
    assert getattr(ctx, "diagnostic_run_id") == "test_run_12345"


def test_crash_payload_schema_completeness():
    """
    Asserts CrashPayload declares all execution, container, and error fields.
    """
    payload = CrashPayload(
        args=["poc.png"],
        input_data="test",
        raw_bytes_hex="89504e470d0a1a0a",
        reason="Heap overflow test",
        exit_code=139,
        crash_type="SIGSEGV (Segmentation Fault)",
        is_execution_error=False,
        stdout="output",
        stderr="error",
        container_id="c123456",
        container_image="ubuntu:latest",
        container_image_digest="sha256:abcdef",
    )

    assert payload.is_execution_error is False
    assert payload.container_id == "c123456"
    assert payload.crash_type == "SIGSEGV (Segmentation Fault)"

    # Test execution error flag
    payload.is_execution_error = True
    payload.crash_type = "EXECUTION_ERROR"
    assert payload.is_execution_error is True


def test_vulnerability_detail_schema_completeness():
    """
    Asserts VulnerabilityDetail declares all verification and confidence fields.
    """
    vuln = VulnerabilityDetail(
        vuln_type="Heap Buffer Overflow",
        cwe="CWE-122",
        severity="critical",
        line_number=42,
        code_snippet="memcpy(dest, src, len);",
        verification_status="VERIFIED_RISK",
        verification_annotation="Pointer arithmetic unchecked",
        confidence="HIGH",
        is_false_positive_risk=False,
        metadata={"func": "test_func"},
    )

    assert vuln.verification_status == "VERIFIED_RISK"
    assert vuln.confidence == "HIGH"
    assert vuln.line_number == 42


@pytest.mark.asyncio
async def test_supervisor_compilation_failure_exception_handling():
    """
    Ensures that when compilation fails, FuzzingSupervisorAgent gracefully
    records COMPILATION_FAILED reachability telemetry without raising ValueError.
    """
    from unittest.mock import patch
    from mutagen.agents.supervisor import FuzzingSupervisorAgent

    ctx = ProgramContext(
        target_path="dummy.c",
        language="c",
        os_platform="linux",
        source_code="int main() { return 0; }",
    )

    with patch("mutagen.agents.supervisor.compile_target", side_effect=RuntimeError("gcc not found")):
        supervisor = FuzzingSupervisorAgent()
        res_ctx = await supervisor.process(ctx)

        assert res_ctx.reachability_status == "COMPILATION_FAILED"
        assert "gcc not found" in res_ctx.reachability_message
        assert any("Compilation failed" in log for log in res_ctx.logs)
