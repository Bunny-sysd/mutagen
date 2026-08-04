import asyncio
from unittest.mock import MagicMock, patch
import pytest

from mutagen.agents.patcher import PatchEngineerAgent
from mutagen.agents.supervisor import FuzzingSupervisorAgent
from mutagen.agents.synthesizer import PayloadSynthesizerAgent
from mutagen.agents.triage import TriageAgent
from mutagen.agents.validator import StructuralValidatorAgent
from mutagen.state import CrashPayload, PatchProposal, ProgramContext, VulnerabilityDetail
from mutagen.static_analyzer import StaticFinding


# ============================================================================
# 1. State Model Adapter & Boundary Enforcement Unit Tests
# ============================================================================

def test_vulnerability_detail_from_any_dict():
    raw_dict = {
        "vuln_type": "Buffer Overflow",
        "cwe": "CWE-120",
        "severity": "critical",
        "line_number": 42,
        "code_snippet": "strcpy(buf, input);"
    }
    vuln = VulnerabilityDetail.from_any(raw_dict)
    assert isinstance(vuln, VulnerabilityDetail)
    assert vuln.vuln_type == "Buffer Overflow"
    assert vuln.cwe == "CWE-120"
    assert vuln.line_number == 42


def test_vulnerability_detail_from_any_static_finding_dataclass():
    finding = StaticFinding(
        function_name="main",
        line=10,
        pattern_type="unsafe_copy",
        call_name="strcpy",
        severity="critical",
        cwe="CWE-120",
        context_snippet="strcpy(a, b);"
    )
    vuln = VulnerabilityDetail.from_any(finding)
    assert isinstance(vuln, VulnerabilityDetail)
    assert vuln.cwe == "CWE-120"
    assert vuln.line_number == 10
    assert "strcpy" in vuln.vuln_type or "strcpy" in vuln.code_snippet


def test_vulnerability_detail_from_any_invalid_type_fails_loudly():
    with pytest.raises(TypeError) as excinfo:
        VulnerabilityDetail.from_any(12345)
    assert "[StateBoundaryError]" in str(excinfo.value)


def test_crash_payload_from_any_dict_str_bytes():
    payload_dict = CrashPayload.from_any({"args": ["overflow"], "input_data": "AAAA"})
    assert isinstance(payload_dict, CrashPayload)
    assert payload_dict.args == ["overflow"]
    assert payload_dict.input_data == "AAAA"

    payload_str = CrashPayload.from_any("BBBB")
    assert isinstance(payload_str, CrashPayload)
    assert payload_str.input_data == "BBBB"

    payload_bytes = CrashPayload.from_any(b"\x00\xff")
    assert isinstance(payload_bytes, CrashPayload)
    assert payload_bytes.raw_bytes_hex == "00ff"


def test_crash_payload_from_any_invalid_type_fails_loudly():
    with pytest.raises(TypeError) as excinfo:
        CrashPayload.from_any(object())
    assert "[StateBoundaryError]" in str(excinfo.value)


def test_program_context_boundary_field_validation():
    # Coerces raw dicts automatically during context initialization
    context = ProgramContext(
        target_path="",
        language="c",
        os_platform="win32",
        source_code="",
        vulnerabilities=[{"vuln_type": "Format String", "cwe": "CWE-134", "severity": "high", "line_number": 5, "code_snippet": "printf(arg)"}],
        active_payloads=[{"args": ["test"]}]
    )

    assert isinstance(context.vulnerabilities[0], VulnerabilityDetail)
    assert isinstance(context.active_payloads[0], CrashPayload)

    # Validates helper methods
    added_v = context.add_vulnerability({"vuln_type": "Command Injection", "cwe": "CWE-78", "severity": "critical", "line_number": 2, "code_snippet": "system(cmd)"})
    assert isinstance(added_v, VulnerabilityDetail)
    assert len(context.vulnerabilities) == 2

    added_p = context.add_payload("payload_string")
    assert isinstance(added_p, CrashPayload)
    assert len(context.active_payloads) == 2


# ============================================================================
# 2. Agent Handoff & Simulated API Failure Regression Tests
# ============================================================================

def test_triage_agent_simulated_gemini_503_fallback_boundary():
    async def run_test():
        code = "void main() { char b[10]; strcpy(b, 'test'); }"
        context = ProgramContext(target_path="", language="c", os_platform="win32", source_code=code)

        with patch("mutagen.agents.triage.get_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.client.models.generate_content.side_effect = Exception("503 ServerError: Service Unavailable")
            mock_get_engine.return_value = mock_engine

            agent = TriageAgent(model_provider="gemini", model_name="gemini-2.5-flash")
            res = await agent.process(context)

            assert len(res.vulnerabilities) > 0
            for v in res.vulnerabilities:
                assert isinstance(v, VulnerabilityDetail)
                assert v.cwe != ""

    asyncio.run(run_test())


def test_synthesizer_agent_simulated_gemini_503_fallback_boundary():
    async def run_test():
        code = "void main() { char b[10]; strcpy(b, 'test'); }"
        vuln = VulnerabilityDetail(vuln_type="Buffer Overflow", cwe="CWE-120", severity="critical", line_number=1, code_snippet="strcpy(b, input);")
        context = ProgramContext(target_path="", language="c", os_platform="win32", source_code=code, vulnerabilities=[vuln])

        with patch("mutagen.agents.synthesizer.get_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.client.models.generate_content.side_effect = Exception("503 ServerError: Service Unavailable")
            mock_get_engine.return_value = mock_engine

            agent = PayloadSynthesizerAgent(model_provider="gemini", model_name="gemini-2.5-flash")
            res = await agent.process(context)

            assert len(res.active_payloads) > 0
            for p in res.active_payloads:
                assert isinstance(p, CrashPayload)

    asyncio.run(run_test())


def test_patcher_and_validator_agent_contract():
    async def run_test():
        code = "int main() { return 0; }"
        payload = CrashPayload(args=["A" * 100], crash_type="SIGSEGV")
        context = ProgramContext(target_path="main.c", language="c", os_platform="win32", source_code=code, active_payloads=[payload])

        with patch("mutagen.agents.patcher.get_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.generate_patch.return_value = "int main() { return 0; }"
            mock_get_engine.return_value = mock_engine

            patcher = PatchEngineerAgent()
            res_patcher = await patcher.process(context)

            assert res_patcher.get_primary_patch() == "int main() { return 0; }"

    asyncio.run(run_test())
