"""
Unit tests for Mutagen's 504/timeout resilience, model candidate retries, and CVE typo normalization.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from mutagen.cve_validator import fetch_cve_metadata, normalize_cve_id
from mutagen.engines.gemini import GeminiEngine


class TestRetryAndTimeoutResilience(unittest.TestCase):
    def test_normalize_cve_id_typos(self):
        """Validates that CVE typos (5-digit years, spaces, lowercase, underscores) normalize cleanly."""
        self.assertEqual(normalize_cve_id("CVE-20250-64505"), "CVE-2025-64505")
        self.assertEqual(normalize_cve_id("cve-20250-64505"), "CVE-2025-64505")
        self.assertEqual(normalize_cve_id("cve_2025_64505"), "CVE-2025-64505")
        self.assertEqual(normalize_cve_id("CVE 2025 64505"), "CVE-2025-64505")
        self.assertEqual(normalize_cve_id("CVE2025-64505"), "CVE-2025-64505")

    def test_fetch_cve_metadata_with_typo(self):
        """Validates that fetch_cve_metadata returns high-fidelity metadata even with a typo."""
        meta = fetch_cve_metadata("CVE-20250-64505")
        self.assertEqual(meta["cve_id"], "CVE-2025-64505")
        self.assertIn("png_do_quantize", meta["affected_functions"])
        self.assertEqual(meta["fixed_version"], "1.6.51")

    def test_gemini_error_classifier_retry_on_attempt_zero(self):
        """Validates that _classify_and_handle_error retries on attempt 0 for 504/timeouts and skips on attempt 1."""
        engine = GeminiEngine(api_key="test_key")

        # Attempt 0 with 504 should return retry
        action0, wait0 = engine._classify_and_handle_error(Exception("504 Gateway Timeout"), attempt=0)
        self.assertEqual(action0, "retry")
        self.assertGreater(wait0, 0)

        # Attempt 1 with 504 should return skip_model
        action1, wait1 = engine._classify_and_handle_error(Exception("504 Gateway Timeout"), attempt=1)
        self.assertEqual(action1, "skip_model")

        # 404 NOT_FOUND should immediately return skip_model on attempt 0
        action_404, wait_404 = engine._classify_and_handle_error(Exception("404 NOT_FOUND: model not supported"), attempt=0)
        self.assertEqual(action_404, "skip_model")
        self.assertEqual(wait_404, 0)

        # 429 RESOURCE_EXHAUSTED should return retry with wait
        action_429, wait_429 = engine._classify_and_handle_error(Exception("429 RESOURCE_EXHAUSTED"), attempt=0)
        self.assertEqual(action_429, "retry")
        self.assertGreater(wait_429, 0)

    @patch("google.genai.Client")
    def test_gemini_multi_candidate_failover(self, mock_client_cls):
        """Tests that when candidate 1 fails with 404, GeminiEngine transparently falls back to candidate 2."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        engine = GeminiEngine(api_key="test_key", model="gemini-invalid-404")

        mock_success_resp = MagicMock()
        mock_success_resp.text = json.dumps({"payloads": [{"args": ["good_gemini"], "reason": "success"}]})

        # First call (candidate 1) raises 404, second call (candidate 2) succeeds
        mock_client.models.generate_content.side_effect = [
            Exception("404 NOT_FOUND: model not found"),
            mock_success_resp
        ]

        payloads = engine.generate_payloads("int main() {}", "Synthesize payloads", max_payloads=1)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["args"], ["good_gemini"])
        self.assertEqual(mock_client.models.generate_content.call_count, 2)

    @patch("anthropic.Anthropic")
    def test_claude_multi_candidate_failover(self, mock_anthropic_cls):
        """Tests that when candidate 1 fails with 404, ClaudeEngine transparently falls back to candidate 2."""
        from mutagen.engines.claude import ClaudeEngine
        from mutagen.models import PayloadItem, PayloadList
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        engine = ClaudeEngine(api_key="test_key", model="claude-invalid-404")

        mock_msg = MagicMock()
        mock_msg.parsed = PayloadList(payloads=[PayloadItem(args=["good_claude"], reason="ok")])

        # Candidate 1 raises 404, Candidate 2 parses successfully
        mock_client.beta.messages.parse.side_effect = [
            Exception("404 model_not_found: Model does not exist"),
            mock_msg
        ]

        payloads = engine.generate_payloads("int main() {}", "Synthesize payloads", max_payloads=1)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["args"], ["good_claude"])
        self.assertEqual(mock_client.beta.messages.parse.call_count, 2)

    @patch("openai.OpenAI")
    def test_openai_multi_candidate_failover(self, mock_openai_cls):
        """Tests that when candidate 1 fails with 404, OpenAIEngine transparently falls back to candidate 2."""
        from mutagen.engines.openai_engine import OpenAIEngine
        from mutagen.models import PayloadItem, PayloadList
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        engine = OpenAIEngine(api_key="test_key", model="gpt-invalid-404")

        mock_choice = MagicMock()
        mock_choice.message.parsed = PayloadList(payloads=[PayloadItem(args=["good_openai"], reason="ok")])
        mock_resp = MagicMock(choices=[mock_choice])

        # Candidate 1 raises 404, Candidate 2 parses successfully
        mock_client.beta.chat.completions.parse.side_effect = [
            Exception("404 The model `gpt-invalid-404` does not exist"),
            mock_resp
        ]

        payloads = engine.generate_payloads("int main() {}", "Synthesize payloads", max_payloads=1)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["args"], ["good_openai"])
        self.assertEqual(mock_client.beta.chat.completions.parse.call_count, 2)


if __name__ == "__main__":
    unittest.main()
