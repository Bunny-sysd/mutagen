"""Tests for the Persistent Fuzzing Supervisor (session_supervisor.py)."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mutagen.session_supervisor import (
    SessionResult,
    SessionSupervisor,
    StepResult,
    _check_oracles,
    _classify_crash,
    _extract_coverage,
    _strip_coverage_marker,
)

# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------

class TestClassifyCrash:
    """Tests for the crash classification function."""

    def test_access_violation(self):
        assert "ACCESS_VIOLATION" in _classify_crash(-1073741819)

    def test_sigsegv(self):
        assert "SIGSEGV" in _classify_crash(-11)

    def test_sigabrt(self):
        assert "SIGABRT" in _classify_crash(-6)

    def test_rust_panic(self):
        assert "RUST_PANIC" in _classify_crash(101)

    def test_unknown_signal(self):
        assert "SIGNAL_99" in _classify_crash(-99)

    def test_normal_exit_code(self):
        assert _classify_crash(1) == "none"

    def test_zero_exit(self):
        assert _classify_crash(0) == "none"


class TestExtractCoverage:
    """Tests for coverage marker extraction."""

    def test_parses_coverage_markers(self):
        text = "some output\n__MUTAGEN_COV__:1,3,7,12\nmore output"
        assert _extract_coverage(text) == [1, 3, 7, 12]

    def test_empty_coverage(self):
        assert _extract_coverage("no coverage here") == []

    def test_empty_marker(self):
        assert _extract_coverage("__MUTAGEN_COV__:") == []


class TestStripCoverageMarker:
    """Tests for coverage marker removal from output."""

    def test_strips_marker(self):
        text = "hello\n__MUTAGEN_COV__:1,2,3\nworld"
        result = _strip_coverage_marker(text)
        assert "__MUTAGEN_COV__" not in result
        assert "hello" in result
        assert "world" in result

    def test_no_marker(self):
        assert _strip_coverage_marker("clean output") == "clean output"


class TestCheckOracles:
    """Tests for logical exploit and heap corruption oracle detection."""

    def test_logical_exploit_detected(self):
        crashed, crash_type = _check_oracles("access granted", "", 0)
        assert crashed is True
        assert "LOGICAL_EXPLOIT" in crash_type

    def test_hard_heap_signature(self):
        crashed, crash_type = _check_oracles("", "AddressSanitizer: heap-buffer-overflow", 0)
        assert crashed is True
        assert "HEAP_CORRUPTION" in crash_type

    def test_soft_heap_with_normal_exit(self):
        """Soft heap signatures with exit code 0 or 1 should NOT crash."""
        crashed, _ = _check_oracles("buffer overflow handled", "", 0)
        assert crashed is False

    def test_soft_heap_with_abnormal_exit(self):
        """Soft heap signatures with abnormal exit code SHOULD crash."""
        crashed, crash_type = _check_oracles("buffer overflow", "", -11)
        assert crashed is True
        assert "HEAP_CORRUPTION" in crash_type

    def test_clean_output(self):
        crashed, crash_type = _check_oracles("hello world", "", 0)
        assert crashed is False
        assert crash_type == "none"


# ---------------------------------------------------------------------------
# SessionSupervisor tests (mocked subprocess)
# ---------------------------------------------------------------------------

class TestSessionSupervisorStdin:
    """Tests for SessionSupervisor in session:stdin mode."""

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_start_spawns_process(self, mock_popen):
        """start() should spawn a Popen with stdin/stdout/stderr pipes."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()

        mock_popen.assert_called_once()
        call_kwargs = mock_popen.call_args
        assert call_kwargs[1]["stdin"] == subprocess.PIPE
        assert call_kwargs[1]["stdout"] == subprocess.PIPE
        assert call_kwargs[1]["stderr"] == subprocess.PIPE
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_double_start_raises(self, mock_popen):
        """Starting an already-started session should raise RuntimeError."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()
        with pytest.raises(RuntimeError, match="already started"):
            sup.start()
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_is_alive_running(self, mock_popen):
        """is_alive should return True when process is running."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Still running
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()
        assert sup.is_alive is True
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_is_alive_dead(self, mock_popen):
        """is_alive should return False when process has exited."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0  # Exited
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()
        assert sup.is_alive is False
        sup.kill()

    def test_send_step_without_start(self):
        """Sending a step without starting should return SESSION_NOT_STARTED."""
        sup = SessionSupervisor("target.exe", "session:stdin")
        result = sup.send_step("hello")
        assert result.is_alive is False
        assert result.crash_type == "SESSION_NOT_STARTED"

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_send_step_to_dead_process(self, mock_popen):
        """Sending to a dead process should return crash info."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = -11  # SIGSEGV
        mock_proc.returncode = -11
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()
        result = sup.send_step("crash_payload")
        assert result.is_alive is False
        assert "SIGSEGV" in result.crash_type
        assert result.return_code == -11
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_kill_cleans_up(self, mock_popen):
        """kill() should terminate the process and reset state."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin")
        sup.start()
        sup.kill()

        mock_proc.kill.assert_called_once()
        assert sup.is_alive is False
        assert sup._started is False

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_context_manager(self, mock_popen):
        """Context manager should auto-start and auto-kill."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        with SessionSupervisor("target.exe", "session:stdin") as sup:
            assert sup._started is True

        mock_proc.kill.assert_called_once()


class TestSessionSupervisorTcp:
    """Tests for SessionSupervisor in session:tcp mode."""

    @patch("mutagen.session_supervisor.socket.socket")
    @patch("mutagen.session_supervisor.subprocess.Popen")
    @patch("mutagen.session_supervisor.time.sleep")
    def test_tcp_start_connects(self, mock_sleep, mock_popen, mock_socket_cls):
        """TCP mode should spawn process and connect a persistent socket."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        sup = SessionSupervisor("server.exe", "session:tcp:9090")
        sup.start()

        mock_popen.assert_called_once()
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 9090))
        mock_sock.settimeout.assert_called()
        sup.kill()

    @patch("mutagen.session_supervisor.socket.socket")
    @patch("mutagen.session_supervisor.subprocess.Popen")
    @patch("mutagen.session_supervisor.time.sleep")
    def test_tcp_kill_closes_socket(self, mock_sleep, mock_popen, mock_socket_cls):
        """kill() should close the TCP socket."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        sup = SessionSupervisor("server.exe", "session:tcp:9090")
        sup.start()
        sup.kill()

        mock_sock.close.assert_called_once()


class TestRunSequence:
    """Tests for the run_sequence convenience method."""

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_sequence_stops_on_crash(self, mock_popen):
        """run_sequence should stop feeding inputs after a crash."""
        mock_proc = MagicMock()
        # Process is alive for first 2 calls, dies on 3rd
        mock_proc.poll.side_effect = [None, None, None, None, -11, -11, -11]
        mock_proc.returncode = -11
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin", step_timeout=0.1)
        sup.start()

        # Mock send_step to simulate sequence behavior
        step_results = [
            StepResult(step_index=0, input_sent="AUTH admin", is_alive=True, crash_type="none"),
            StepResult(step_index=1, input_sent="SELECT channel", is_alive=True, crash_type="none"),
            StepResult(step_index=2, input_sent="AAAA"*100, is_alive=False, return_code=-11, crash_type="SIGSEGV (Segmentation Fault)"),
        ]
        with patch.object(sup, "send_step", side_effect=step_results):
            result = sup.run_sequence(["AUTH admin", "SELECT channel", "AAAA"*100, "extra_step"])

        assert result.crashed is True
        assert result.crash_step == 2
        assert "SIGSEGV" in result.crash_type
        assert len(result.steps) == 3  # Stopped at crash, didn't execute 4th
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_sequence_completes_without_crash(self, mock_popen):
        """run_sequence should process all steps when no crash occurs."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin", step_timeout=0.1)
        sup.start()

        step_results = [
            StepResult(step_index=0, input_sent="step1", is_alive=True, crash_type="none",
                       cumulative_coverage={1, 2}),
            StepResult(step_index=1, input_sent="step2", is_alive=True, crash_type="none",
                       cumulative_coverage={1, 2, 3}),
            StepResult(step_index=2, input_sent="step3", is_alive=True, crash_type="none",
                       cumulative_coverage={1, 2, 3, 4}),
        ]
        with patch.object(sup, "send_step", side_effect=step_results):
            result = sup.run_sequence(["step1", "step2", "step3"])

        assert result.crashed is False
        assert result.crash_step is None
        assert len(result.steps) == 3
        assert result.total_coverage == {1, 2, 3, 4}
        assert len(result.coverage_progression) == 3
        sup.kill()

    @patch("mutagen.session_supervisor.subprocess.Popen")
    def test_sequence_auto_starts(self, mock_popen):
        """run_sequence should auto-start if not already started."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_popen.return_value = mock_proc

        sup = SessionSupervisor("target.exe", "session:stdin", step_timeout=0.1)
        assert sup._started is False

        step_results = [
            StepResult(step_index=0, input_sent="hello", is_alive=True, crash_type="none"),
        ]
        with patch.object(sup, "send_step", side_effect=step_results):
            result = sup.run_sequence(["hello"])

        assert len(result.steps) == 1
        assert result.crashed is False
        sup.kill()


class TestStepResult:
    """Tests for StepResult dataclass defaults."""

    def test_default_values(self):
        r = StepResult(step_index=0, input_sent="test")
        assert r.stdout_delta == ""
        assert r.stderr_delta == ""
        assert r.coverage_delta == []
        assert r.is_alive is True
        assert r.return_code is None
        assert r.crash_type == "none"
        assert r.elapsed_ms == 0.0


class TestSessionResult:
    """Tests for SessionResult dataclass defaults."""

    def test_default_values(self):
        r = SessionResult()
        assert r.steps == []
        assert r.crashed is False
        assert r.crash_step is None
        assert r.crash_type == "none"
        assert r.total_coverage == set()
        assert r.coverage_progression == []

    def test_crash_attribution(self):
        """SessionResult should correctly attribute crash to the right step."""
        r = SessionResult(
            crashed=True,
            crash_step=2,
            crash_type="SIGSEGV (Segmentation Fault)",
            return_code=-11,
        )
        assert r.crash_step == 2
        assert "SIGSEGV" in r.crash_type


class TestInvalidDeliveryMode:
    """Tests for unsupported delivery modes."""

    def test_invalid_mode_raises(self):
        """Unsupported delivery mode should raise ValueError on start()."""
        sup = SessionSupervisor("target.exe", "session:udp:1234")
        with pytest.raises(ValueError, match="Unsupported session delivery mode"):
            sup.start()

    def test_inner_mode_extraction(self):
        """_inner_mode should strip the 'session:' prefix."""
        sup = SessionSupervisor("target.exe", "session:stdin")
        assert sup._inner_mode() == "stdin"

        sup2 = SessionSupervisor("target.exe", "session:tcp:8080")
        assert sup2._inner_mode() == "tcp:8080"
