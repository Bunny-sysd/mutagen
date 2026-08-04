import asyncio
from unittest.mock import MagicMock, patch
import pytest

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
