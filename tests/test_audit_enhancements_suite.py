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

    def test_make_png_chunk_and_repair(self):
        """Verify _make_png_chunk builds valid chunks and _repair_png parses and recalculates CRCs."""
        import zlib
        from mutagen.agents.synthesizer import _make_png_chunk, _generate_file_mode_fallback_payloads
        from mutagen.binary_repair import repair_binary_payload

        # Test _make_png_chunk
        data = b"\x01\x02\x03\x04"
        chunk = _make_png_chunk(b"PLTE", data)
        self.assertEqual(len(chunk), 4 + 4 + 4 + 4)  # len + type + data + crc
        expected_crc = zlib.crc32(b"PLTE" + data) & 0xFFFFFFFF
        actual_crc = int.from_bytes(chunk[-4:], "big")
        self.assertEqual(actual_crc, expected_crc)

        # Test fallback PNG generation
        payloads = _generate_file_mode_fallback_payloads("target/pngrtran.c", "png_do_quantize palette plte")
        self.assertGreaterEqual(len(payloads), 1)
        poc = payloads[0]
        self.assertIn("overflow_poc.png", poc["args"])
        raw_bytes = bytes.fromhex(poc["raw_bytes_hex"])
        self.assertTrue(raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

        # Test repair_binary_payload parses PNG without corrupting chunks
        repaired = repair_binary_payload(raw_bytes, target_hint="pngrtran.c")
        self.assertTrue(repaired.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", repaired)
        self.assertIn(b"PLTE", repaired)
        self.assertIn(b"IDAT", repaired)
        self.assertIn(b"IEND", repaired)

    def test_sniper_mode_cve_token_slicing(self):
        """Verify analyze_source in Sniper Mode strictly matches CVE functions and reduces lines."""
        from mutagen.static_analyzer import analyze_source

        dummy_large_source = "\n".join([
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "typedef int png_size_t;",
            "void helper1() { printf('1'); }",
            "void helper2() { printf('2'); }",
            "void png_do_quantize(int *row, int len) {",
            "    // Target function body",
            "    int buffer[10];",
            "    for (int i = 0; i < len; i++) {",
            "        buffer[i] = row[i];",
            "    }",
            "}",
            "void other_func() { malloc(100); }",
        ] + [f"void extra_{i}() {{ int x = {i}; }}" for i in range(100)])

        res = analyze_source(dummy_large_source, target_functions=["png_do_quantize"])
        self.assertTrue(res.reduction_percent > 50.0)
        self.assertIn("png_do_quantize", res.focused_code)
        self.assertNotIn("extra_99", res.focused_code)


if __name__ == "__main__":
    unittest.main()
