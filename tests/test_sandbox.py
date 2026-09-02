import subprocess
from unittest.mock import MagicMock, patch

from mutagen.executor import _check_docker_functional, execute_payload


def test_check_docker_functional_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "version", "--format", "{{.Server.Version}}"], returncode=0, stdout="27.0.1", stderr=""
        )
        assert _check_docker_functional(force_refresh=True) is True

def test_check_docker_functional_failure():
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = Exception("Docker not running")
        # Ensure it returns False and doesn't crash the program
        assert _check_docker_functional(force_refresh=True) is False

def test_execute_payload_no_sandbox():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["target_exe", "arg1"], returncode=0, stdout="OK", stderr=""
        )
        res = execute_payload("target_exe", ["arg1"], None, "args", 5, "none")
        assert res["crashed"] is False
        assert mock_run.call_args[0][0] == ["target_exe", "arg1"]

def test_execute_payload_docker_sandbox_fallback():
    import os
    with patch.dict(os.environ, {"CI": "", "MUTAGEN_ALLOW_UNSANDBOXED": "1"}, clear=False):
        with patch("sys.stdin.isatty", return_value=True):
            with patch("mutagen.executor._check_docker_functional", return_value=False):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = subprocess.CompletedProcess(
                        args=["target_exe", "arg1"], returncode=0, stdout="OK", stderr=""
                    )
                    res = execute_payload("target_exe", ["arg1"], None, "args", 5, "docker")
                    assert res["crashed"] is False
                    # Command should be executed directly on the host (not containerized)
                    assert mock_run.call_args[0][0] == ["target_exe", "arg1"]

def test_execute_payload_docker_sandbox_active():
    with patch("mutagen.executor._check_docker_functional", return_value=True):
        with patch("os.path.abspath", return_value="/workspace/target_exe"):
            with patch("os.path.dirname", return_value="/workspace"):
                with patch("os.path.basename", return_value="target_exe"):
                    def side_effect(cmd, *args, **kwargs):
                        if cmd[0] == "docker" and cmd[1] == "inspect":
                            return subprocess.CompletedProcess(cmd, returncode=0, stdout="ubuntu@sha256:1234567890abcdef", stderr="")
                        elif cmd[0] == "docker" and cmd[1] == "create":
                            return subprocess.CompletedProcess(cmd, returncode=0, stdout="container123456789", stderr="")
                        elif cmd[0] == "docker" and cmd[1] == "start":
                            return subprocess.CompletedProcess(cmd, returncode=0, stdout="OK", stderr="")
                        elif cmd[0] == "docker" and cmd[1] == "rm":
                            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
                        return subprocess.CompletedProcess(cmd, returncode=0, stdout="OK", stderr="")

                    with patch("subprocess.run", side_effect=side_effect):
                        res = execute_payload("target_exe", ["arg1"], None, "args", 5, "docker")
                        assert res["crashed"] is False
                        assert res["container_id"] == "container123"
                        assert res["container_image_digest"] == "ubuntu@sha256:1234567890abcdef"

def test_execute_payload_docker_sandbox_tcp_mode():
    with patch("mutagen.executor._check_docker_functional", return_value=True):
        with patch("os.path.abspath", return_value="/workspace/target_exe"):
            with patch("os.path.dirname", return_value="/workspace"):
                with patch("os.path.basename", return_value="target_exe"):
                    create_cmds = []
                    def side_effect(cmd, *args, **kwargs):
                        if cmd[0] == "docker" and cmd[1] == "create":
                            create_cmds.append(cmd)
                            return subprocess.CompletedProcess(cmd, returncode=0, stdout="container123456789", stderr="")
                        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

                    with patch("subprocess.run", side_effect=side_effect):
                        with patch("subprocess.Popen") as mock_popen:
                            mock_proc = MagicMock()
                            mock_proc.communicate.return_value = ("OK", "")
                            mock_proc.poll.return_value = 0
                            mock_proc.returncode = 0
                            mock_popen.return_value = mock_proc

                            # Mock socket connectivity to prevent actual connection attempt during test
                            with patch("socket.socket"):
                                execute_payload("target_exe", [], "input_payload", "tcp:8080", 5, "docker")

                                assert len(create_cmds) > 0
                                called_args = create_cmds[0]
                                assert "docker" in called_args
                                assert "-p" in called_args
                                assert "8080:8080" in called_args
                                assert "--network=none" not in called_args
