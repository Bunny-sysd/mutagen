import subprocess
from unittest.mock import MagicMock, patch
import pytest
from mutagen.executor import execute_payload

def test_execute_payload_success():
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Hello"
        mock_res.stderr = ""
        mock_run.return_value = mock_res
        
        result = execute_payload("some_exe", ["arg1"], "", "args", 5)
        
        assert result["crashed"] is False
        assert result["crash_type"] == "none"
        assert result["return_code"] == 0
        assert result["stdout"] == "Hello"

def test_execute_payload_stdin_success():
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Received standard input"
        mock_res.stderr = ""
        mock_run.return_value = mock_res
        
        result = execute_payload("some_exe", [], "hello input", "stdin", 5)
        
        assert result["crashed"] is False
        assert result["crash_type"] == "none"
        assert result["return_code"] == 0
        
        # Verify that subprocess.run was called with input parameter
        mock_run.assert_called_once_with(
            ["some_exe"],
            input="hello input",
            capture_output=True,
            text=True,
            timeout=5
        )

def test_execute_payload_crash_access_violation():
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = -1073741819
        mock_res.stdout = ""
        mock_res.stderr = "Access violation"
        mock_run.return_value = mock_res
        
        result = execute_payload("some_exe", ["arg1"], "", "args", 5)
        
        assert result["crashed"] is True
        assert "ACCESS_VIOLATION" in result["crash_type"]
        assert result["return_code"] == -1073741819

def test_execute_payload_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["some_exe"], timeout=5)):
        result = execute_payload("some_exe", ["arg1"], "", "args", 5)
        
        assert result["crashed"] is True
        assert "TIMEOUT" in result["crash_type"]
        assert result["return_code"] == -1
