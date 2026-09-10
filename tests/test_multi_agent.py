from unittest.mock import MagicMock, patch

import pytest

from mutagen.orchestrator import AgentOrchestrator
from mutagen.state import CrashPayload, ProgramContext, VulnerabilityDetail


def test_context_state_serialization():
    detail = VulnerabilityDetail(
        vuln_type="Buffer Overflow",
        cwe="CWE-120",
        severity="critical",
        line_number=10,
        code_snippet="char buf[10]; strcpy(buf, input);"
    )

    payload = CrashPayload(
        args=["arg1"],
        input_data="A" * 100
    )

    context = ProgramContext(
        target_path="test_target.c",
        language="c",
        os_platform="win32",
        source_code="int main() { return 0; }",
        vulnerabilities=[detail],
        active_payloads=[payload]
    )

    assert context.vulnerabilities[0].vuln_type == "Buffer Overflow"
    assert context.active_payloads[0].input_data == "A" * 100
    assert context.verification_status == "UNVERIFIED"

@pytest.mark.anyio
@patch("mutagen.engines.get_engine")
@patch("mutagen.agents.triage.TriageAgent.process")
@patch("mutagen.agents.synthesizer.PayloadSynthesizerAgent.process")
@patch("mutagen.agents.supervisor.FuzzingSupervisorAgent.process")
@patch("mutagen.agents.patcher.PatchEngineerAgent.process")
@patch("mutagen.agents.validator.StructuralValidatorAgent.process")
async def test_orchestrator_flow(mock_validator, mock_patcher, mock_supervisor, mock_synthesizer, mock_triage, mock_get_engine):
    # Mock engine instantiation to avoid GenAI client verification
    mock_get_engine.return_value = MagicMock()

    # Setup mocks to return updated contexts
    async def triage_side_effect(ctx):
        ctx.vulnerabilities.append(VulnerabilityDetail(
            vuln_type="Buffer Overflow", cwe="CWE-120", severity="critical", line_number=10, code_snippet=""
        ))
        return ctx

    async def synth_side_effect(ctx):
        ctx.active_payloads.append(CrashPayload(args=["abort"], input_data="abort"))
        return ctx

    async def supervisor_side_effect(ctx):
        ctx.active_payloads[0].crash_type = "ACCESS_VIOLATION"
        ctx.active_payloads[0].exit_code = -1073741819
        return ctx

    async def patch_side_effect(ctx):
        ctx.proposed_patches["primary_patch"] = "void main() {}"
        return ctx

    async def validator_side_effect(ctx):
        ctx.verification_status = "VERIFIED_SECURE"
        return ctx

    mock_triage.side_effect = triage_side_effect
    mock_synthesizer.side_effect = synth_side_effect
    mock_supervisor.side_effect = supervisor_side_effect
    mock_patcher.side_effect = patch_side_effect
    mock_validator.side_effect = validator_side_effect

    orchestrator = AgentOrchestrator(
        target_path="dummy.c",
        source_code="int main() { return 0; }",
        provider="gemini",
        model="gemini-2.5-flash",
        compiler="gcc",
        api_key="mock_key"
    )

    final_context = await orchestrator.run()

    assert len(final_context.vulnerabilities) == 1
    assert len(final_context.active_payloads) == 1
    assert final_context.active_payloads[0].crash_type == "ACCESS_VIOLATION"
    assert final_context.proposed_patches["primary_patch"] == "void main() {}"
    assert final_context.verification_status == "VERIFIED_SECURE"


@pytest.mark.anyio
@patch("mutagen.engines.get_engine")
@patch("mutagen.agents.triage.TriageAgent.process")
@patch("mutagen.agents.synthesizer.PayloadSynthesizerAgent.process")
@patch("mutagen.agents.supervisor.FuzzingSupervisorAgent.process")
async def test_orchestrator_discards_untested_duplicate_batch(mock_supervisor, mock_synthesizer, mock_triage, mock_get_engine):
    """Regression test: when the stagnation guard detects a synthesizer batch
    identical to the previous one and stops the loop, that batch was already
    appended to active_payloads by the synthesizer but never tested by the
    supervisor. It must be discarded, not left in the final payload count."""
    mock_get_engine.return_value = MagicMock()

    async def triage_side_effect(ctx):
        ctx.vulnerabilities.append(VulnerabilityDetail(
            vuln_type="Buffer Overflow", cwe="CWE-120", severity="critical", line_number=10, code_snippet=""
        ))
        return ctx

    async def synth_side_effect(ctx):
        # Synthesizes the exact same 3 payloads every batch (e.g. persistent API
        # quota exhaustion falling back to the same deterministic template each time).
        for i in range(3):
            ctx.add_payload(CrashPayload(args=[f"fallback_{i}.png"], input_data="", raw_bytes_hex="deadbeef"))
        return ctx

    async def supervisor_side_effect(ctx):
        return ctx  # never crashes

    mock_triage.side_effect = triage_side_effect
    mock_synthesizer.side_effect = synth_side_effect
    mock_supervisor.side_effect = supervisor_side_effect

    orchestrator = AgentOrchestrator(
        target_path="dummy.c", source_code="int main() { return 0; }",
        provider="gemini", model="gemini-2.5-flash", compiler="gcc", api_key="mock_key",
        max_payloads=0,
    )
    final_context = await orchestrator.run()

    # Batch 1 (3 payloads) gets tested; batch 2 is detected as an identical
    # duplicate and must be discarded before testing.
    assert mock_synthesizer.call_count == 2
    assert len(final_context.active_payloads) == 3


@pytest.mark.anyio
@patch("mutagen.engines.get_engine")
@patch("mutagen.agents.triage.TriageAgent.process")
@patch("mutagen.agents.synthesizer.PayloadSynthesizerAgent.process")
@patch("mutagen.agents.supervisor.FuzzingSupervisorAgent.process")
async def test_orchestrator_detects_stagnation_despite_deduped_filenames(mock_supervisor, mock_synthesizer, mock_triage, mock_get_engine):
    """Regression test: PayloadSynthesizerAgent auto-uniquifies each payload's
    displayed filename across the whole run (so reports don't show duplicate
    labels for genuinely different content). The stagnation guard must not be
    fooled by that into thinking every batch is "new" -- it needs to compare
    actual payload content (raw_bytes_hex/input_data), not the filename, or a
    run stuck on persistent synthesis failure (same fallback content every
    batch, different auto-deduped filename each time) would never stop."""
    mock_get_engine.return_value = MagicMock()

    async def triage_side_effect(ctx):
        ctx.vulnerabilities.append(VulnerabilityDetail(
            vuln_type="Buffer Overflow", cwe="CWE-120", severity="critical", line_number=10, code_snippet=""
        ))
        return ctx

    call_count = {"n": 0}

    async def synth_side_effect(ctx):
        # Same content every batch, but a distinct (auto-deduped-style) filename
        # per payload per batch -- matches real PayloadSynthesizerAgent behavior
        # under persistent synthesis failure.
        call_count["n"] += 1
        base = (call_count["n"] - 1) * 3
        for i in range(3):
            ctx.add_payload(CrashPayload(args=[f"poc_fallback_{base + i + 1}.png"], input_data="", raw_bytes_hex=f"deadbeef0{i}"))
        return ctx

    async def supervisor_side_effect(ctx):
        return ctx  # never crashes

    mock_triage.side_effect = triage_side_effect
    mock_synthesizer.side_effect = synth_side_effect
    mock_supervisor.side_effect = supervisor_side_effect

    orchestrator = AgentOrchestrator(
        target_path="dummy.c", source_code="int main() { return 0; }",
        provider="gemini", model="gemini-2.5-flash", compiler="gcc", api_key="mock_key",
        max_payloads=0,
    )
    final_context = await orchestrator.run()

    assert call_count["n"] == 2, f"expected the loop to detect content-level stagnation and stop after batch 2, got {call_count['n']} batches"
    assert len(final_context.active_payloads) == 3
