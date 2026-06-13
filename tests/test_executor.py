import subprocess
from unittest.mock import MagicMock, patch, call
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


# --- TCP DELIVERY MODE TESTS -----------------------------------------------

def test_execute_payload_tcp_success():
    """Verify TCP delivery: launches server, connects via socket, sends data."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = ("[+] Received data", "")
    mock_process.args = ["some_exe"]

    mock_sock = MagicMock()

    with patch("subprocess.Popen", return_value=mock_process) as mock_popen, \
         patch("socket.socket", return_value=mock_sock), \
         patch("time.sleep"):  # Skip the 0.5s wait in tests

        result = execute_payload("some_exe", [], "AAAA", "tcp:8888", 5)

        # Verify the server process was launched
        mock_popen.assert_called_once_with(
            ["some_exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Verify socket connected to the right port
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 8888))
        mock_sock.sendall.assert_called_once_with(b"AAAA")
        mock_sock.close.assert_called_once()

        # Verify result
        assert result["crashed"] is False
        assert result["return_code"] == 0


def test_execute_payload_tcp_crash():
    """TCP mode: server crashes after receiving data."""
    mock_process = MagicMock()
    mock_process.returncode = -1073741819  # ACCESS_VIOLATION
    mock_process.communicate.return_value = ("", "segfault")
    mock_process.args = ["vuln_server"]

    mock_sock = MagicMock()

    with patch("subprocess.Popen", return_value=mock_process), \
         patch("socket.socket", return_value=mock_sock), \
         patch("time.sleep"):

        result = execute_payload("vuln_server", [], "A" * 256, "tcp:9999", 5)

        assert result["crashed"] is True
        assert "ACCESS_VIOLATION" in result["crash_type"]
        assert result["return_code"] == -1073741819


def test_execute_payload_tcp_timeout():
    """TCP mode: server hangs and gets killed after timeout."""
    mock_process = MagicMock()
    mock_process.communicate.side_effect = subprocess.TimeoutExpired(
        cmd=["hang_server"], timeout=5
    )
    mock_process.kill = MagicMock()
    # After kill, communicate returns
    def post_kill_communicate(*a, **kw):
        return ("", "killed")
    mock_process.kill.side_effect = lambda: setattr(
        mock_process, 'communicate',
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["hang_server"], timeout=5))
    )

    mock_sock = MagicMock()

    with patch("subprocess.Popen", return_value=mock_process), \
         patch("socket.socket", return_value=mock_sock), \
         patch("time.sleep"):

        result = execute_payload("hang_server", [], "data", "tcp:7777", 5)

        assert result["crashed"] is True
        assert "TIMEOUT" in result["crash_type"]


def test_execute_payload_tcp_socket_connect_fails():
    """TCP mode: socket connection fails (server died immediately), should not crash the fuzzer."""
    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = ("", "bind failed")
    mock_process.args = ["dead_server"]

    mock_sock = MagicMock()
    mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")

    with patch("subprocess.Popen", return_value=mock_process), \
         patch("socket.socket", return_value=mock_sock), \
         patch("time.sleep"):

        # Should NOT raise — the fuzzer should handle this gracefully
        result = execute_payload("dead_server", [], "payload", "tcp:5555", 5)

        # Non-zero exit but not a crash signal → not crashed
        assert result["crashed"] is False


def test_execute_payload_tcp_logical_exploit():
    """TCP mode: server prints auth bypass indicator."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = ("ACCESS GRANTED: root shell", "")
    mock_process.args = ["auth_server"]

    mock_sock = MagicMock()

    with patch("subprocess.Popen", return_value=mock_process), \
         patch("socket.socket", return_value=mock_sock), \
         patch("time.sleep"):

        result = execute_payload("auth_server", [], "admin\npassword", "tcp:4444", 5)

        assert result["crashed"] is True
        assert "LOGICAL_EXPLOIT" in result["crash_type"]
        assert "access granted" in result["crash_type"]


# --- CRASH DEDUPLICATION TESTS -----------------------------------------------

def test_crash_signature_deduplication():
    """Verify the _crash_signature function produces consistent dedup keys."""
    from mutagen.core import _crash_signature

    crash_a = {"crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "vuln_type": "buffer_overflow"}
    crash_b = {"crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "vuln_type": "buffer_overflow"}
    crash_c = {"crash_type": "SIGSEGV", "return_code": -11, "vuln_type": "use_after_free"}

    # Same crash type + return code + vuln → same signature
    assert _crash_signature(crash_a) == _crash_signature(crash_b)

    # Different crash → different signature
    assert _crash_signature(crash_a) != _crash_signature(crash_c)


def test_crash_signature_different_vuln_types():
    """Two crashes with same return code but different vuln types are NOT deduped."""
    from mutagen.core import _crash_signature

    crash_a = {"crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "vuln_type": "buffer_overflow"}
    crash_b = {"crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "vuln_type": "format_string"}

    assert _crash_signature(crash_a) != _crash_signature(crash_b)

