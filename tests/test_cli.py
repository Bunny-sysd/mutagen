import os
import sys
from unittest.mock import patch, MagicMock
import pytest

from mutagen.cli import load_env, main

def test_load_env_parsing(tmp_path):
    env_content = """
    # This is a comment
    MUTAGEN_PROVIDER=openai
    MUTAGEN_MODEL='gpt-4o'
    GEMINI_API_KEY = "dummy_gemini_key"
    """
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")

    # Temporarily patch os.getcwd() to return tmp_path so load_env finds the test file
    with patch("os.getcwd", return_value=str(tmp_path)), patch.dict(os.environ, {}, clear=True):
        load_env()
        assert os.environ.get("MUTAGEN_PROVIDER") == "openai"
        assert os.environ.get("MUTAGEN_MODEL") == "gpt-4o"
        assert os.environ.get("GEMINI_API_KEY") == "dummy_gemini_key"

@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_defaults_with_env(mock_run_fuzzer, mock_load_env):
    # Mock sys.argv to simulate a call: mutagen --target targets/01_buffer_overflow.c
    test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c"]
    
    with patch.dict(os.environ, {
        "MUTAGEN_PROVIDER": "openai",
        "MUTAGEN_MODEL": "gpt-4-test",
        "MUTAGEN_API_KEY": "test_global_key"
    }, clear=True), patch("sys.argv", test_args):
        main()
        
        # Verify run_fuzzer kwargs
        mock_run_fuzzer.assert_called_once()
        _, called_kwargs = mock_run_fuzzer.call_args
        assert called_kwargs["provider"] == "openai"
        assert called_kwargs["model"] == "gpt-4-test"
        assert called_kwargs["api_key"] == "test_global_key"

@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_gemini_fallback_key(mock_run_fuzzer, mock_load_env):
    test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--provider", "gemini"]
    with patch.dict(os.environ, {
        "MUTAGEN_API_KEY": "fallback_gemini_key"
    }, clear=True), patch("sys.argv", test_args):
        main()
        mock_run_fuzzer.assert_called_once()
        _, called_kwargs = mock_run_fuzzer.call_args
        assert called_kwargs["provider"] == "gemini"
        assert called_kwargs["api_key"] == "fallback_gemini_key"

@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_openai_fallback_key(mock_run_fuzzer, mock_load_env):
    test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--provider", "openai"]
    with patch.dict(os.environ, {
        "MUTAGEN_API_KEY": "fallback_openai_key"
    }, clear=True), patch("sys.argv", test_args):
        main()
        mock_run_fuzzer.assert_called_once()
        _, called_kwargs = mock_run_fuzzer.call_args
        assert called_kwargs["provider"] == "openai"
        assert called_kwargs["api_key"] == "fallback_openai_key"

@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_claude_fallback_key(mock_run_fuzzer, mock_load_env):
    test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--provider", "claude"]
    with patch.dict(os.environ, {
        "MUTAGEN_API_KEY": "fallback_claude_key"
    }, clear=True), patch("sys.argv", test_args):
        main()
        mock_run_fuzzer.assert_called_once()
        _, called_kwargs = mock_run_fuzzer.call_args
        assert called_kwargs["provider"] == "claude"
        assert called_kwargs["api_key"] == "fallback_claude_key"

@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_specific_key_overrides_fallback(mock_run_fuzzer, mock_load_env):
    test_args = ["mutagen", "--target", "targets/01_buffer_overflow.c", "--provider", "gemini"]
    with patch.dict(os.environ, {
        "GEMINI_API_KEY": "specific_gemini_key",
        "MUTAGEN_API_KEY": "fallback_key"
    }, clear=True), patch("sys.argv", test_args):
        main()
        mock_run_fuzzer.assert_called_once()
        _, called_kwargs = mock_run_fuzzer.call_args
        assert called_kwargs["api_key"] == "specific_gemini_key"


@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_binary_routing(mock_run_fuzzer, mock_load_env):
    """Test that a binary target correctly routes with binary_mode=True and flags."""
    test_args = [
        "mutagen", 
        "--target", "targets/01_buffer_overflow.exe", 
        "--provider", "gemini",
        "--decompile-all",
        "--ghidra-path", "C:\\ghidra_install"
    ]
    with patch.dict(os.environ, {
        "GEMINI_API_KEY": "specific_gemini_key",
    }, clear=True), patch("sys.argv", test_args):
        # We also mock os.path.exists for the target to ensure main does not fail on file not found
        with patch("os.path.exists", return_value=True):
            main()
            mock_run_fuzzer.assert_called_once()
            _, called_kwargs = mock_run_fuzzer.call_args
            assert called_kwargs["binary_mode"] is True
            assert called_kwargs["decompile_all"] is True
            assert called_kwargs["ghidra_path"] == "C:\\ghidra_install"
            assert called_kwargs["gcc_path"] == ""


@patch("mutagen.cli.load_env")
@patch("mutagen.cli.run_fuzzer")
def test_cli_ci_mode_ignores_binaries(mock_run_fuzzer, mock_load_env):
    """Test that CI/CD mode diff checking ignores binary targets."""
    mock_run_fuzzer.return_value = 0
    # Mock sys.argv to run in CI mode
    test_args = ["mutagen", "--ci"]
    
    # Mock git commands to return a binary target
    import subprocess
    mock_run_proc = MagicMock()
    # Let git diff --name-only return target.exe and target.c
    mock_run_proc.stdout = "targets/target.exe\ntargets/target.c\n"
    mock_run_proc.returncode = 0
    
    with patch("subprocess.run", return_value=mock_run_proc), \
         patch("sys.argv", test_args), \
         patch("os.path.exists", return_value=True), \
         patch.dict(os.environ, {"GEMINI_API_KEY": "test_key"}, clear=True):
         
        # We expect mutagen to warning/ignore target.exe and only pass target.c to run_fuzzer
        main()
        
        # Verify run_fuzzer was called but NEVER with target.exe
        assert mock_run_fuzzer.call_count > 0
        for call in mock_run_fuzzer.call_args_list:
            _, called_kwargs = call
            assert not called_kwargs["source_path"].endswith("target.exe")


