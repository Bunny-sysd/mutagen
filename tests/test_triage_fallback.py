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


def test_triage_failure_fallback_upgrades_delivery_mode_for_file_io_target():
    """
    Regression test: a prior version hardcoded delivery_mode to "args"
    unconditionally on triage failure, discarding whatever the correct mode
    should actually be. For a file-parsing target (e.g. libpng, with genuine
    file I/O primitives like png_create_read_struct/png_init_io), this forced
    the fallback synthesis path to treat the target as an args-mode CLI tool,
    producing a junk "AAAA..." payload that could never reach the parser at
    all instead of a real file-shaped payload.
    """
    async def run_test():
        c_code = """
        #include "png.h"
        void read_target(const char *filename) {
            png_structp png_ptr = png_create_read_struct(NULL, NULL, NULL, NULL);
            FILE *fp = fopen(filename, "rb");
            png_init_io(png_ptr, fp);
        }
        """
        context = ProgramContext(
            target_path="pngtest.c",
            language="c",
            os_platform="linux",
            source_code=c_code,
            delivery_mode="args",
        )

        with patch("mutagen.agents.triage.get_engine") as mock_get_engine, patch("time.sleep"):
            mock_engine = MagicMock()
            mock_engine.client.models.generate_content.side_effect = Exception("429 RESOURCE_EXHAUSTED")
            mock_get_engine.return_value = mock_engine

            agent = TriageAgent(model_provider="gemini", model_name="gemini-2.5-flash")
            res_context = await agent.process(context)

            assert res_context.delivery_mode == "file"

    asyncio.run(run_test())


def test_triage_failure_fallback_prioritizes_and_caps_cve_findings():
    """
    Regression test: the static analyzer fallback added every single finding
    to context.vulnerabilities with no limit -- a large source file could
    produce hundreds of findings, burying the one finding that actually
    matches the Ground-Truth CVE's documented target function among noise
    (and risking it being dropped entirely once downstream stages sample or
    truncate the list). In CVE mode, any finding whose enclosing function or
    call matches the CVE's affected function(s) must always survive, and the
    total must be capped to stay actionable.
    """
    async def run_test():
        lines = ['#include "png.h"']
        for i in range(60):
            lines.append(f"void noise_func_{i}(char *p) {{ char b[8]; strcpy(b, p); }}")
        lines.append("void png_read_row(png_structp png_ptr) { png_init_io(png_ptr, NULL); png_do_quantize(png_ptr); }")
        c_code = "\n".join(lines)

        context = ProgramContext(
            target_path="pngrtran.c", language="c", os_platform="linux",
            source_code=c_code, delivery_mode="args",
        )
        context.cve_meta = {"cve_id": "CVE-2025-64505", "affected_functions": ["png_do_quantize", "png_set_quantize", "png_quantize"]}
        context.validate_cve = "CVE-2025-64505"

        with patch("mutagen.agents.triage.get_engine") as mock_get_engine, patch("time.sleep"):
            mock_engine = MagicMock()
            mock_engine.client.models.generate_content.side_effect = Exception("429 RESOURCE_EXHAUSTED")
            mock_get_engine.return_value = mock_engine

            agent = TriageAgent(model_provider="gemini", model_name="gemini-2.5-flash")
            res_context = await agent.process(context)

            assert len(res_context.vulnerabilities) <= 25
            matched = [v for v in res_context.vulnerabilities if "png_do_quantize" in (v.code_snippet or "") or "png_do_quantize" in v.vuln_type]
            assert len(matched) >= 1, "the CVE-relevant finding must survive the cap"

    asyncio.run(run_test())


def test_triage_success_path_injects_cve_target_when_ai_drifts():
    """
    Regression test: the CVE-prioritization fix above only applies when the
    AI triage call fails entirely and falls back to static analysis. When the
    AI call SUCCEEDS but reports findings unrelated to the CVE's documented
    target function -- observed in practice: the AI reporting an unrelated
    integer-overflow or buffer-overlap finding instead of the CVE's actual
    target -- nothing enforced that the real function ever got represented,
    so synthesis could spend an entire run never generating a single payload
    for the actual vulnerability. If none of the AI's own findings reference
    the CVE's target function, a real, AST-verified static finding for it
    must be injected and prioritized first.
    """
    import json

    async def run_test():
        lines = ['#include "png.h"']
        for i in range(20):
            lines.append(f"void noise_func_{i}(char *p) {{ char b[8]; strcpy(b, p); }}")
        lines.append("void png_do_read_transformations(png_structp png_ptr) { png_do_quantize(png_ptr); }")
        c_code = "\n".join(lines)

        context = ProgramContext(
            target_path="pngrtran.c", language="c", os_platform="linux",
            source_code=c_code, delivery_mode="file",
        )
        context.cve_meta = {"cve_id": "CVE-2025-64505", "affected_functions": ["png_do_quantize", "png_set_quantize", "png_quantize"]}
        context.validate_cve = "CVE-2025-64505"

        agent = TriageAgent(api_key="k")
        fake_response = MagicMock()
        fake_response.text = json.dumps({
            "vulnerabilities": [
                {"vuln_type": "Integer Overflow in num_entries", "cwe": "CWE-190", "severity": "high", "line_number": 2, "code_snippet": "char b[8]; strcpy(b, p);", "reason": "unrelated to the CVE"},
            ],
            "suggested_delivery_mode": "file",
        })

        with patch.object(agent.engine, "client", MagicMock()) as mock_client:
            mock_client.models.generate_content.return_value = fake_response
            await agent.process(context)

        assert len(context.vulnerabilities) == 2
        first = context.vulnerabilities[0]
        assert "png_do_quantize" in first.code_snippet or "png_do_quantize" in first.vuln_type

    asyncio.run(run_test())


def test_triage_success_path_does_not_duplicate_when_ai_already_targets_cve():
    """When the AI's own finding already references the CVE's target
    function, no synthetic finding should be injected."""
    import json

    async def run_test():
        c_code = '#include "png.h"\nvoid png_do_read_transformations(png_structp png_ptr) { png_do_quantize(png_ptr); }\n'
        context = ProgramContext(
            target_path="pngrtran.c", language="c", os_platform="linux",
            source_code=c_code, delivery_mode="file",
        )
        context.cve_meta = {"cve_id": "CVE-2025-64505", "affected_functions": ["png_do_quantize"]}
        context.validate_cve = "CVE-2025-64505"

        agent = TriageAgent(api_key="k")
        fake_response = MagicMock()
        fake_response.text = json.dumps({
            "vulnerabilities": [
                {"vuln_type": "Heap over-read in png_do_quantize", "cwe": "CWE-125", "severity": "critical", "line_number": 2, "code_snippet": "png_do_quantize(png_ptr);", "reason": "correct"},
            ],
            "suggested_delivery_mode": "file",
        })

        with patch.object(agent.engine, "client", MagicMock()) as mock_client:
            mock_client.models.generate_content.return_value = fake_response
            await agent.process(context)

        assert len(context.vulnerabilities) == 1

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


