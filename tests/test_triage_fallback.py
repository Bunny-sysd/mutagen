import asyncio
from unittest.mock import MagicMock, mock_open, patch

from mutagen.agents.triage import TriageAgent, _normalize_finding
from mutagen.state import ProgramContext, VulnerabilityDetail
from mutagen.static_analyzer import StaticFinding


def test_normalize_finding_dict():
    item = {
        "vuln_type": "Buffer Overflow",
        "cwe": "CWE-120",
        "severity": "critical",
        "line_number": 42,
        "code_snippet": "strcpy(buf, input);",
        "reason": "Unbounded copy"
    }
    detail = _normalize_finding(item)
    assert isinstance(detail, VulnerabilityDetail)
    assert detail.vuln_type == "Buffer Overflow"
    assert detail.cwe == "CWE-120"
    assert detail.line_number == 42
    assert detail.code_snippet == "strcpy(buf, input);"
    assert detail.metadata["reason"] == "Unbounded copy"


def test_normalize_finding_static_finding_dataclass():
    finding = StaticFinding(
        function_name="vulnerable_func",
        line=15,
        pattern_type="unsafe_copy",
        call_name="strcpy",
        severity="critical",
        cwe="CWE-120",
        context_snippet="strcpy(buffer, user_input);"
    )
    detail = _normalize_finding(finding)
    assert isinstance(detail, VulnerabilityDetail)
    assert detail.vuln_type == "Static Finding (strcpy)"
    assert detail.cwe == "CWE-120"
    assert detail.line_number == 15
    assert detail.code_snippet == "strcpy(buffer, user_input);"
    assert detail.metadata["reason"] == "Dangerous call 'strcpy' identified by static analyzer"


def test_triage_agent_gemini_failure_fallback():
    async def run_test():
        c_code = """
        #include <stdio.h>
        #include <string.h>
        void vuln(char *input) {
            char buf[64];
            strcpy(buf, input);
        }
        """
        context = ProgramContext(
            target_path="",
            language="c",
            os_platform="win32",
            source_code=c_code,
            delivery_mode="args"
        )

        with patch("mutagen.agents.triage.get_engine") as mock_get_engine:
            mock_engine = MagicMock()
            mock_engine.client.models.generate_content.side_effect = Exception("503 ServerError: Service Unavailable")
            mock_get_engine.return_value = mock_engine

            agent = TriageAgent(model_provider="gemini", model_name="gemini-2.5-flash")
            res_context = await agent.process(context)

            # Assert process completes without throwing AttributeError
            assert len(res_context.vulnerabilities) > 0
            for vuln in res_context.vulnerabilities:
                assert isinstance(vuln, VulnerabilityDetail)
                assert vuln.cwe != ""
                assert vuln.line_number >= 1
                assert "strcpy" in vuln.code_snippet or "strcpy" in vuln.vuln_type
            assert any("Error during triage LLM call" in log for log in res_context.logs)

    asyncio.run(run_test())


@patch("mutagen.core.get_engine")
@patch("mutagen.core.compile_target")
@patch("mutagen.core.execute_payload")
@patch("mutagen.core.save_crash_report")
@patch("builtins.open", new_callable=mock_open, read_data="int main() { return 0; }")
@patch("os.makedirs")
@patch("mutagen.core.validate_c_source")
def test_legacy_pipeline_empty_analyze_code_fallback_path(mock_ast_validate, mock_makedirs, mock_file, mock_save, mock_execute, mock_compile, mock_get_engine):
    """Validates that when engine.analyze_code() returns [] in legacy pipeline mode,
    the pipeline falls back to mutation payloads tagged with is_fallback/synthesis_failed."""
    from mutagen.core import run_fuzzer

    mock_ast_validate.return_value = MagicMock(is_valid=True, errors=[], functions_found=["main"], has_main=True, node_count=10)

    mock_engine = MagicMock()
    # Force AI analysis to fail/return empty list
    mock_engine.analyze_code.return_value = []
    mock_engine.generate_exploit.return_value = "import sys; sys.exit(0)"
    mock_engine.generate_patch.return_value = "int main() { return 0; }"
    mock_engine.refine_patch.return_value = "int main() { return 0; }"
    mock_get_engine.return_value = mock_engine

    mock_compile.return_value = "dummy_binary.exe"
    mock_execute.return_value = {
        "crashed": True,
        "crash_type": "ACCESS_VIOLATION",
        "return_code": -11,
        "stdout": "",
        "stderr": "Segmentation fault",
        "container_id": "",
        "container_image": "",
        "container_image_digest": "",
    }
    mock_save.return_value = ("report.json", "report.html")

    # Run legacy pipeline
    crashes_count = run_fuzzer(
        source_path="targets/dummy.c",
        api_key="dummy_key",
        gcc_path="gcc",
        max_payloads=5,
        timeout=5,
        debug=False,
        mode="pipeline",
        sandbox="none"
    )

    assert crashes_count >= 1
    # Check that save_crash_report was called with fallback payloads
    mock_save.assert_called_once()
    saved_crashes = mock_save.call_args[0][0]
    assert len(saved_crashes) >= 1
    for c in saved_crashes:
        # Fallback mutation payloads must carry fallback / mutator markers
        assert c.get("is_fallback") is True or "Traditional mutator" in c.get("reason", "")


