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

def test_execute_payload_logical_exploit():
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "ACCESS GRANTED: Admin privileges acquired!"
        mock_res.stderr = ""
        mock_run.return_value = mock_res
        
        result = execute_payload("some_exe", ["arg1"], "", "args", 5)
        
        assert result["crashed"] is True
        assert "LOGICAL_EXPLOIT" in result["crash_type"]
        assert "access granted" in result["crash_type"]
        assert result["return_code"] == 0

def test_compiler_check_sanitizer_support():
    from mutagen.compiler import check_sanitizer_support
    
    # Test fallback if using Tiny C Compiler (tcc)
    assert check_sanitizer_support("tcc.exe") is False
    assert check_sanitizer_support("c:\\mutagen\\tcc\\tcc\\tcc.exe") is False
    
    # Test check returning True if subprocess succeeds
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_run.return_value = mock_res
        
        assert check_sanitizer_support("gcc") is True
        
    # Test check returning False if subprocess fails or throws exception
    with patch("subprocess.run", side_effect=Exception("error")):
        assert check_sanitizer_support("gcc") is False

def test_compile_target_raises_compilation_error():
    from mutagen.compiler import compile_target, CompilationError
    
    with patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "syntax error: expected ';'"
        mock_run.return_value = mock_res
        
        with pytest.raises(CompilationError) as exc_info:
            compile_target("dummy.c", "gcc")
            
        assert "syntax error" in str(exc_info.value)
