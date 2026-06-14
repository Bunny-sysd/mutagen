import os
import sys
from unittest.mock import patch
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
