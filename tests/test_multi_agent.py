import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from mutagen.state import ProgramContext, VulnerabilityDetail, CrashPayload
from mutagen.orchestrator import AgentOrchestrator

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
