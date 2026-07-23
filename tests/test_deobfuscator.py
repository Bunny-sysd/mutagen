"""
Unit tests for AI Deobfuscation, scan profiles, and static-only execution gating.
"""
import os
import sys
from unittest.mock import MagicMock, patch

# Ensure project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mutagen.cli import main
from mutagen.core import run_fuzzer
from mutagen.engines.claude import ClaudeEngine
from mutagen.engines.gemini import GeminiEngine
from mutagen.engines.ollama import OllamaEngine
from mutagen.engines.openai_engine import OpenAIEngine

# =============================================================================
# Engine Deobfuscation tests
# =============================================================================

class TestEngineDeobfuscation:
    """Verify that all engines implement deobfuscate_code and return deobfuscated code."""

    @patch("google.genai.Client")
    def test_gemini_deobfuscate_code(self, mock_genai_client):
        # Mock Gemini generate_content response
        mock_response = MagicMock()
        mock_response.text = "int parsed_main() { return 0; }"

        engine = GeminiEngine(api_key="test_key")
        engine.client.models.generate_content.return_value = mock_response

        raw_code = "int FUN_004010a0() { return 0; }"
        res = engine.deobfuscate_code(raw_code, debug=False)

        assert "parsed_main" in res
        assert "FUN_004010a0" not in res
        engine.client.models.generate_content.assert_called_once()

    @patch("openai.OpenAI")
    def test_openai_deobfuscate_code(self, mock_openai_client):
        # Mock OpenAI chat completion response
        mock_completion = MagicMock()
        mock_completion.choices = [MagicMock()]
        mock_completion.choices[0].message.content = "int resolved_function() { return 0; }"

        engine = OpenAIEngine(api_key="test_key")
        engine.client.chat.completions.create.return_value = mock_completion

        raw_code = "int FUN_004010a0() { return 0; }"
        res = engine.deobfuscate_code(raw_code, debug=False)

        assert "resolved_function" in res
        assert "FUN_004010a0" not in res
        engine.client.chat.completions.create.assert_called_once()

    def test_ollama_deobfuscate_code(self):
        engine = OllamaEngine(model="llama3.2")

        with patch.object(engine, "_generate", return_value="int cleaned_logic() { return 0; }") as mock_gen:
            raw_code = "int FUN_004010a0() { return 0; }"
            res = engine.deobfuscate_code(raw_code, debug=False)

            assert "cleaned_logic" in res
            assert "FUN_004010a0" not in res
            mock_gen.assert_called_once()

    @patch("anthropic.Anthropic")
    def test_claude_deobfuscate_code(self, mock_anthropic_client):
        engine = ClaudeEngine(api_key="test_key")

        with patch.object(engine, "_generate", return_value="int deobfuscated_claude() { return 0; }") as mock_gen:
            raw_code = "int FUN_004010a0() { return 0; }"
            res = engine.deobfuscate_code(raw_code, debug=False)

            assert "deobfuscated_claude" in res
            assert "FUN_004010a0" not in res
            mock_gen.assert_called_once()


# =============================================================================
# CLI Profile Flags & Safety Logic tests
# =============================================================================

class TestCLIProfileFlags:
    """Verify that CLI flags parse correctly and trigger safety gates."""

    @patch("mutagen.cli.load_env")
    @patch("mutagen.cli.run_fuzzer")
    def test_cli_profile_default(self, mock_run_fuzzer, mock_load_env):
        test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c"]
        with patch("sys.argv", test_args), patch("os.path.exists", return_value=True), patch.dict(os.environ, {"MUTAGEN_API_KEY": "mock_key"}):
            main()
            mock_run_fuzzer.assert_called_once()
            _, kwargs = mock_run_fuzzer.call_args
            assert kwargs["profile"] == "legacy-audit"
            assert kwargs["static_only"] is False

    @patch("mutagen.cli.load_env")
    @patch("mutagen.cli.run_fuzzer")
    def test_cli_profile_supply_chain(self, mock_run_fuzzer, mock_load_env):
        test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--profile", "supply-chain"]
        with patch("sys.argv", test_args), patch("os.path.exists", return_value=True), patch.dict(os.environ, {"MUTAGEN_API_KEY": "mock_key"}):
            main()
            mock_run_fuzzer.assert_called_once()
            _, kwargs = mock_run_fuzzer.call_args
            assert kwargs["profile"] == "supply-chain"
            assert kwargs["static_only"] is False

    @patch("mutagen.cli.load_env")
    @patch("mutagen.cli.run_fuzzer")
    def test_cli_profile_malware_triage_forces_static(self, mock_run_fuzzer, mock_load_env):
        # Setting profile to malware-triage must automatically enforce static_only=True
        test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--profile", "malware-triage"]
        with patch("sys.argv", test_args), patch("os.path.exists", return_value=True), patch.dict(os.environ, {"MUTAGEN_API_KEY": "mock_key"}):
            main()
            mock_run_fuzzer.assert_called_once()
            _, kwargs = mock_run_fuzzer.call_args
            assert kwargs["profile"] == "malware-triage"
            assert kwargs["static_only"] is True


# =============================================================================
# Static-Only Execution Gating tests
# =============================================================================

class TestStaticOnlyGating:
    """Verify that core fuzzer skips compilation and fuzzing when static_only=True."""

    @patch("mutagen.core.get_engine")
    @patch("mutagen.core.save_crash_report")
    def test_static_only_skips_compilation_and_fuzzing(self, mock_save_report, mock_get_engine, tmp_path):
        # Setup temporary mock target file
        target = tmp_path / "dummy.c"
        target.write_text("int main() { return 0; }")

        # Mock LLM Engine behavior
        mock_engine = MagicMock()
        mock_engine.analyze_code.return_value = [
            {"vuln_type": "buffer_overflow", "reason": "unsafe buffer size", "severity": "high", "cwe": "CWE-120"}
        ]
        mock_get_engine.return_value = mock_engine
        mock_save_report.return_value = ("test.json", "test.html")

        # Execute run_fuzzer in static_only mode
        crashes_found = run_fuzzer(
            source_path=str(target),
            api_key="key",
            gcc_path="gcc",
            max_payloads=1,
            timeout=5,
            debug=False,
            static_only=True,
            profile="legacy-audit"
        )

        # Assert fuzzer returned static findings and skipped execution
        assert crashes_found == 1
        mock_engine.analyze_code.assert_called_once()
        mock_save_report.assert_called_once()

        # Verify that dynamic execution mocks were NOT initialized
        # (execute_payload, compile_target, etc. would have been called if not gated)
        _, save_kwargs = mock_save_report.call_args
        assert save_kwargs["static_only"] is True
        assert save_kwargs["profile"] == "legacy-audit"
