import os
import unittest
from unittest.mock import MagicMock, patch

from mutagen.cli import is_supported_language
from mutagen.cve_validator import render_cve_validation_panel
from mutagen.reachability_checker import select_best_reachable_binary
from mutagen.reporter import save_crash_report
from mutagen.session_supervisor import SessionResult, StepResult


class TestAuditEnhancementsSuite(unittest.TestCase):

    def test_reporter_subdirectory_target_path(self):
        """Verify save_crash_report handles targets with path separators without FileNotFoundError."""
        crashes = [{
            "vuln_type": "buffer_overflow",
            "cwe": "CWE-120",
            "line_number": 42,
            "crash_type": "SIGSEGV",
            "reason": "Stack buffer overflow",
            "args": ["-p", "AAAA"],
            "return_code": -11,
        }]
        target_with_dirs = "targets/deep/nested/vulnerable_prog.c"
        json_file, html_file = save_crash_report(crashes, target_with_dirs, total_tested=1)
        self.assertTrue(os.path.exists(json_file))
        self.assertTrue(os.path.exists(html_file))
        self.assertIn("crashes", html_file)
        # Verify HTML contains report content
        with open(html_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("MUTAGEN", content)
            self.assertIn("buffer_overflow", content)

    def test_cve_validator_category_f_panel(self):
        """Verify render_cve_validation_panel renders Category F without throwing exceptions."""
        result_f = {
            "category": "F",
            "status": "INCONCLUSIVE — SYNTHESIS FAILED",
            "cve_id": "CVE-2026-99999",
            "cve_name": "LibSample Buffer Overflow",
            "summary": "Synthesis failed due to rate limits.",
            "diagnostic": {
                "synthesis_error": "429 Quota Exceeded during payload synthesis"
            }
        }
        # Should render cleanly without throwing exceptions
        render_cve_validation_panel(result_f)

    def test_reachability_empty_candidates(self):
        """Verify select_best_reachable_binary handles empty/filtered candidates gracefully without IndexError."""
        # Completely empty
        cand, info = select_best_reachable_binary([])
        self.assertIsNone(cand)
        self.assertFalse(info["reachable"])

        # All filtered out (e.g. cmake compiler id artifacts)
        cand, info = select_best_reachable_binary(["build/CMakeFiles/compilerIdC.exe"])
        self.assertIsNone(cand)
        self.assertFalse(info["reachable"])

    def test_cli_is_supported_language_python(self):
        """Verify .py is accepted as a supported source language."""
        self.assertTrue(is_supported_language(".py"))
        self.assertTrue(is_supported_language(".PY"))
        self.assertTrue(is_supported_language(".c"))
        self.assertTrue(is_supported_language(".rs"))
        self.assertTrue(is_supported_language(".sol"))

    def test_session_result_mermaid_and_serialization(self):
        """Verify SessionResult generates valid Mermaid sequence diagram and serializable dictionary."""
        s1 = StepResult(step_index=0, input_sent="AUTH test_user", is_alive=True, coverage_delta=[1, 2])
        s2 = StepResult(step_index=1, input_sent="SELECT mailbox_inbox", is_alive=True, coverage_delta=[3])
        s3 = StepResult(step_index=2, input_sent="SEARCH " + "A" * 100, is_alive=False, return_code=-11, crash_type="SIGSEGV (Segmentation Fault)")

        session = SessionResult(
            steps=[s1, s2, s3],
            crashed=True,
            crash_step=2,
            crash_type="SIGSEGV (Segmentation Fault)",
            total_coverage={1, 2, 3},
            return_code=-11
        )

        mermaid = session.to_mermaid_sequence()
        self.assertIn("sequenceDiagram", mermaid)
        self.assertIn("Step 1: \"AUTH test_user\"", mermaid)
        self.assertIn("💥 CRASH", mermaid)

        d = session.to_dict()
        self.assertTrue(d["crashed"])
        self.assertEqual(len(d["steps"]), 3)
        self.assertIn("mermaid_sequence", d)

    def test_claude_openai_structured_output_fields(self):
        """Verify _parse_generate preserves top-level fields like suggested_delivery_mode."""
        from pydantic import BaseModel
        from mutagen.models import VulnItem

        class MockTriageResult(BaseModel):
            vulnerabilities: list[VulnItem]
            suggested_delivery_mode: str

        from mutagen.engines.claude import ClaudeEngine
        from mutagen.engines.openai_engine import OpenAIEngine

        claude = ClaudeEngine(api_key="mock_key")
        openai_eng = OpenAIEngine(api_key="mock_key")

        mock_obj = MockTriageResult(
            vulnerabilities=[VulnItem(vuln_type="buffer_overflow", cwe="CWE-120", reason="Test", severity="high")],
            suggested_delivery_mode="stdin"
        )

        # Mock Claude
        mock_msg = MagicMock()
        mock_msg.parsed = mock_obj
        claude.client = MagicMock()
        claude.client.beta.messages.parse.return_value = mock_msg

        res_claude = claude._parse_generate("prompt", MockTriageResult, "vulnerabilities")
        self.assertIsInstance(res_claude, dict)
        self.assertEqual(res_claude["suggested_delivery_mode"], "stdin")
        self.assertEqual(len(res_claude["vulnerabilities"]), 1)

        # Mock OpenAI
        mock_choice = MagicMock()
        mock_choice.message.parsed = mock_obj
        mock_resp = MagicMock()
        mock_resp.choices = [mock_choice]
        openai_eng.client = MagicMock()
        openai_eng.client.beta.chat.completions.parse.return_value = mock_resp

        res_openai = openai_eng._parse_generate("prompt", MockTriageResult, "vulnerabilities")
        self.assertIsInstance(res_openai, dict)
        self.assertEqual(res_openai["suggested_delivery_mode"], "stdin")
        self.assertEqual(len(res_openai["vulnerabilities"]), 1)


if __name__ == "__main__":
    unittest.main()
