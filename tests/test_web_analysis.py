import pytest
from unittest.mock import MagicMock, patch
import os
from mutagen.cli import is_supported_language
from mutagen.core import run_fuzzer


def test_is_supported_language_web():
    assert is_supported_language(".html") is True
    assert is_supported_language(".htm") is True
    assert is_supported_language(".js") is True
    assert is_supported_language(".ts") is True
    assert is_supported_language(".css") is True
    assert is_supported_language(".sol") is True
    assert is_supported_language(".py") is False


@patch("mutagen.core.get_engine")
@patch("builtins.open")
@patch("os.path.exists")
@patch("os.path.splitext")
def test_run_fuzzer_web_forces_static_only(mock_splitext, mock_exists, mock_open, mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.analyze_code.return_value = [
        {
            "args": [],
            "input_data": "",
            "vuln_type": "client_xss",
            "cwe": "CWE-79",
            "severity": "high",
            "reason": "Uses innerHTML without sanitization"
        }
    ]
    mock_get_engine.return_value = mock_engine

    # Mock file checks
    mock_exists.return_value = True
    mock_splitext.return_value = ("test_script", ".js")

    # Mock reading the JavaScript file
    mock_file = MagicMock()
    mock_file.read.return_value = "document.getElementById('out').innerHTML = location.hash;"
    mock_open.return_value.__enter__.return_value = mock_file

    with patch("mutagen.core.save_crash_report") as mock_save:
        mock_save.return_value = ("report.json", "report.html")

        res = run_fuzzer(
            source_path="test_script.js",
            api_key="mock_key",
            gcc_path="",
            max_payloads=2,
            timeout=5,
            debug=False,
            provider="openai",
            model="gpt-4o",
            static_only=False  # Should be overridden to True automatically
        )

        assert res == 1  # 1 represents the number of static findings detected
        # Verify engine was configured with "javascript" language
        assert mock_engine.language == "javascript"
        # Verify save_crash_report was called with static findings
        mock_save.assert_called_once()
        called_args = mock_save.call_args[0]
        findings = called_args[0]  # First positional argument is static_findings list
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "client_xss"
        assert findings[0]["cwe"] == "CWE-79"
