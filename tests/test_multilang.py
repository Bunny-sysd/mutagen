import os
from unittest.mock import patch

from mutagen.cli import is_supported_language
from mutagen.compiler import compile_target


def test_language_support():
    assert is_supported_language(".go") is True
    assert is_supported_language(".java") is True
    assert is_supported_language(".cs") is True
    assert is_supported_language(".c") is True
    assert is_supported_language(".rs") is True


@patch("subprocess.run")
def test_compile_target_go(mock_run):
    mock_run.return_value.returncode = 0
    with patch("os.name", "nt"):
        out = compile_target("target.go", "go")
        assert out.endswith("target.exe")
        mock_run.assert_called_with(["go", "build", "-o", out, "target.go"], capture_output=True, text=True)


@patch("subprocess.run")
@patch("builtins.open")
@patch("os.chmod")
def test_compile_target_java(mock_chmod, mock_open, mock_run):
    mock_run.return_value.returncode = 0
    out = compile_target("Hello.java", "javac")
    if os.name == 'nt':
        assert out.endswith("Hello.bat")
    else:
        assert out.endswith("Hello.sh")
    assert mock_run.call_args[0][0] == ["javac", "Hello.java"]


@patch("subprocess.run")
def test_compile_target_csharp(mock_run):
    mock_run.return_value.returncode = 0
    with patch("os.name", "nt"):
        out = compile_target("target.cs", "csc")
        assert out.endswith("target.exe")
        mock_run.assert_called_with(["csc", "/out:" + out, "target.cs"], capture_output=True, text=True, env=mock_run.call_args[1]["env"])


