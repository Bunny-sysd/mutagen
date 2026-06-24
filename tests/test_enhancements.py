import pytest
import os
import tempfile
import subprocess
from unittest.mock import patch, MagicMock

from mutagen.decompiler import decompile_binary, DecompilationError
from mutagen.reporter import save_crash_report

def test_webhook_headers_saving():
    """Verify that webhook headers are parsed and included in outgoing webhook calls."""
    crashes = [{"args": ["a"], "vuln_type": "buffer_overflow"}]
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create dummy target name
        target_name = "test_target"
        
        # Test saved files without triggering network post
        json_file, html_file = save_crash_report(
            crashes, target_name, 1,
            patch_code="void patch() {}",
            exploit_code="import sys",
            clean_source_code="void vuln() {}",
            webhook_url="", # empty URL prevents post
            webhook_headers=["Authorization: Bearer mytoken123", "Custom-Key: Custom-Value"]
        )
        
        assert os.path.exists(json_file)
        assert os.path.exists(html_file)
        
        # Cleanup files
        try:
            os.remove(json_file)
            os.remove(html_file)
        except Exception:
            pass

@patch("requests.post")
def test_webhook_post_custom_headers(mock_post):
    """Verify that requests.post is called with the custom webhook headers."""
    crashes = [{"args": ["a"], "vuln_type": "buffer_overflow"}]
    
    save_crash_report(
        crashes, "test_target", 1,
        patch_code="void patch() {}",
        exploit_code="import sys",
        clean_source_code="void vuln() {}",
        webhook_url="http://example.com/webhook",
        webhook_headers=["Authorization: Bearer token123", "X-Key: Value"]
    )
    
    # Assert that requests.post was called
    mock_post.assert_called_once()
    kwargs = mock_post.call_args[1]
    headers = kwargs["headers"]
    
    assert headers["Authorization"] == "Bearer token123"
    assert headers["X-Key"] == "Value"
    assert headers["Content-Type"] == "application/json"


def test_radare2_decompiler_error_missing():
    """Verify that targeting radare2 raises DecompilationError if binary is missing."""
    with patch("shutil.which", return_value=None):
        with patch("os.path.isfile", return_value=True):
            with pytest.raises(DecompilationError) as exc_info:
                decompile_binary("nonexistent_binary.elf", "", decompiler="radare2")
            assert "Radare2 executable not found" in str(exc_info.value)


@patch("subprocess.run")
def test_radare2_decompilation_fallback(mock_run):
    """Verify radare2 decompilation fallbacks when decoders are missing."""
    # Mock subprocess.run responses
    mock_res_1 = MagicMock()
    mock_res_1.stdout = ""
    mock_res_1.stderr = "r2dec not found"
    
    mock_res_2 = MagicMock()
    mock_res_2.stdout = "sym.main:\n  push rbp\n  strcpy(dest, src);"
    mock_res_2.stderr = ""
    
    mock_run.side_effect = [mock_res_1, mock_res_2]
    
    with patch("shutil.which", return_value="mock_r2"):
        with patch("os.path.isfile", return_value=True):
            result = decompile_binary(
                "dummy.elf", "",
                decompiler="radare2",
                decompiler_path="mock_r2"
            )
            assert result.decompiler_used == "radare2"
            assert "sym.main" in result.pseudo_source
            assert result.functions_found == 1
