import pytest
from unittest.mock import patch, MagicMock
import subprocess
import os

from mutagen.executor import execute_payload, _check_docker_functional
from mutagen.cli import main

def test_check_docker_functional_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=0, stdout="CONTAINER ID", stderr=""
        )
        assert _check_docker_functional() is True

def test_check_docker_functional_failure():
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = Exception("Docker not running")
        # Ensure it returns False and doesn't crash the program
        assert _check_docker_functional() is False

def test_execute_payload_no_sandbox():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["target_exe", "arg1"], returncode=0, stdout="OK", stderr=""
        )
        res = execute_payload("target_exe", ["arg1"], None, "args", 5, "none")
        assert res["crashed"] is False
        assert mock_run.call_args[0][0] == ["target_exe", "arg1"]

def test_execute_payload_docker_sandbox_fallback():
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
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = subprocess.CompletedProcess(
                            args=["docker", "run"], returncode=0, stdout="OK", stderr=""
                        )
                        res = execute_payload("target_exe", ["arg1"], None, "args", 5, "docker")
                        assert res["crashed"] is False
                        
                        called_args = mock_run.call_args[0][0]
                        # Verify container wrapper syntax
                        assert "docker" in called_args
                        assert "run" in called_args
                        assert "--memory=512m" in called_args
                        assert "--cpus=1.0" in called_args
                        assert "--network=none" in called_args
                        assert "./target_exe" in called_args
                        assert "arg1" in called_args

def test_execute_payload_docker_sandbox_tcp_mode():
    with patch("mutagen.executor._check_docker_functional", return_value=True):
        with patch("os.path.abspath", return_value="/workspace/target_exe"):
            with patch("os.path.dirname", return_value="/workspace"):
                with patch("os.path.basename", return_value="target_exe"):
                    with patch("subprocess.Popen") as mock_popen:
                        mock_proc = MagicMock()
                        mock_proc.communicate.return_value = ("OK", "")
                        mock_proc.returncode = 0
                        mock_popen.return_value = mock_proc
                        
                        # Mock socket connectivity to prevent actual connection attempt during test
                        with patch("socket.socket") as mock_sock:
                            res = execute_payload("target_exe", [], "input_payload", "tcp:8080", 5, "docker")
                            
                            called_args = mock_popen.call_args[0][0]
                            assert "docker" in called_args
                            assert "-p" in called_args
                            assert "8080:8080" in called_args
                            assert "--network=none" not in called_args
