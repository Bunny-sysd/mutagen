import os
from unittest.mock import MagicMock, patch

from mutagen.compiler import compile_target
from mutagen.engines.gemini import GeminiEngine
from mutagen.engines.ollama import OllamaEngine
from mutagen.executor import execute_payload


def test_engine_language_property():
    """Engines should resolve language properties dynamically."""
    gemini = GeminiEngine(api_key="mock_key")
    assert gemini.lang == "c"
    assert gemini.lang_name == "C"
    assert gemini.lang_ext == "c"

    gemini.language = "rust"
    assert gemini.lang == "rust"
    assert gemini.lang_name == "Rust"
    assert gemini.lang_ext == "rs"

    ollama = OllamaEngine()
    assert ollama.lang == "c"
    assert ollama.lang_name == "C"
    assert ollama.lang_ext == "c"

    ollama.language = "rust"
    assert ollama.lang == "rust"
    assert ollama.lang_name == "Rust"
    assert ollama.lang_ext == "rs"

@patch("subprocess.run")
def test_rust_compilation(mock_run):
    """compile_target should call rustc for .rs files."""
    mock_run.return_value = MagicMock(returncode=0)

    res_path = compile_target("src/main.rs", "rustc")

    expected_ext = ".exe" if os.name == "nt" else ".out"
    assert res_path.endswith(expected_ext)

    mock_run.assert_called_once()
    called_args = mock_run.call_args[0][0]
    assert called_args[0] == "rustc"
    assert called_args[1] == "-o"
    assert called_args[3] == "src/main.rs"

@patch("subprocess.run")
def test_rust_panic_detection(mock_run):
    """execute_payload should identify Rust panic exit code 101 as a crash."""
    mock_response = MagicMock()
    mock_response.returncode = 101
    mock_response.stdout = "thread 'main' panicked at 'index out of bounds'"
    mock_response.stderr = ""
    mock_run.return_value = mock_response

    result = execute_payload("mock_binary.exe", [], "", "args", 5)

    assert result["crashed"] is True
    assert "RUST_PANIC" in result["crash_type"]
    assert result["return_code"] == 101
