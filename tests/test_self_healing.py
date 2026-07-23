from unittest.mock import MagicMock, mock_open, patch

from mutagen.compiler import CompilationError
from mutagen.core import run_fuzzer


@patch("mutagen.core.get_engine")
@patch("mutagen.core.compile_target")
@patch("mutagen.core.execute_payload")
@patch("mutagen.core.save_crash_report")
@patch("builtins.open", new_callable=mock_open, read_data="int main() { return 0; }")
@patch("os.makedirs")
@patch("mutagen.core.validate_c_source")
def test_run_fuzzer_self_healing_compilation_failure(mock_ast_validate, mock_makedirs, mock_file, mock_save_report, mock_execute, mock_compile, mock_get_engine):
    # AST validator always passes (these tests focus on compile/verification failures)
    mock_ast_validate.return_value = MagicMock(is_valid=True, errors=[], functions_found=["main"], has_main=True, node_count=10)
    # Setup mock engine
    mock_engine = MagicMock()
    mock_get_engine.return_value = mock_engine

    # 1 crash found
    mock_engine.analyze_code.return_value = [
        {"vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "high", "args": ["A"*100]}
    ]

    # Executing original payload crashes the target
    mock_execute.side_effect = [
        # First execution during fuzzing phase
        {"crashed": True, "crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "stdout": "", "stderr": ""},
        # Execution during verification phase (attempt 1, since attempt 0 failed compilation)
        {"crashed": False, "crash_type": "none", "return_code": 0, "stdout": "", "stderr": ""}
    ]

    mock_engine.generate_patch.return_value = "bad_patch_code"
    mock_engine.refine_patch.return_value = "good_patch_code"
    mock_engine.generate_exploit.return_value = "exploit_code"

    # Compile target fails the first time, succeeds the second time
    mock_compile.side_effect = [
        "orig_exe", # Original compile during fuzz phase
        CompilationError("compiler error!"), # First patch compile (attempt 0) fails
        "patched_exe" # Second patch compile (attempt 1) succeeds
    ]

    mock_save_report.return_value = ("report.json", "report.html")

    run_fuzzer(
        source_path="dummy.c",
        api_key="key",
        gcc_path="gcc",
        max_payloads=1,
        timeout=5,
        debug=False,
        max_patch_retries=2
    )

    # Check that compile_target was called for the patched files
    assert mock_compile.call_count == 3
    # Check that refine_patch was called once
    mock_engine.refine_patch.assert_called_once_with(
        "int main() { return 0; }",
        "bad_patch_code",
        "The patched C code failed to compile with the following compiler errors:\ncompiler error!",
        {"vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "high", "args": ["A"*100], "payload": "A"*100, "crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "retries": 0, "input_data": "", "reason": "", "stdout": "", "stderr": ""},
        False
    )

@patch("mutagen.core.get_engine")
@patch("mutagen.core.compile_target")
@patch("mutagen.core.execute_payload")
@patch("mutagen.core.save_crash_report")
@patch("builtins.open", new_callable=mock_open, read_data="int main() { return 0; }")
@patch("os.makedirs")
@patch("mutagen.core.validate_c_source")
def test_run_fuzzer_self_healing_verification_crash(mock_ast_validate, mock_makedirs, mock_file, mock_save_report, mock_execute, mock_compile, mock_get_engine):
    # AST validator always passes (these tests focus on verification failures)
    mock_ast_validate.return_value = MagicMock(is_valid=True, errors=[], functions_found=["main"], has_main=True, node_count=10)
    # Setup mock engine
    mock_engine = MagicMock()
    mock_get_engine.return_value = mock_engine

    mock_engine.analyze_code.return_value = [
        {"vuln_type": "buffer_overflow", "cwe": "CWE-120", "severity": "high", "args": ["A"*100]}
    ]

    # Executing original payload crashes, then attempt 0 crashes verification, then attempt 1 passes verification
    mock_execute.side_effect = [
        # First execution during fuzzing phase
        {"crashed": True, "crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "stdout": "", "stderr": ""},
        # Attempt 0 verification: still crashes
        {"crashed": True, "crash_type": "ACCESS_VIOLATION", "return_code": -1073741819, "stdout": "still broken", "stderr": "segmentation fault"},
        # Attempt 1 verification: succeeds
        {"crashed": False, "crash_type": "none", "return_code": 0, "stdout": "", "stderr": ""}
    ]

    mock_engine.generate_patch.return_value = "bad_patch_code"
    mock_engine.refine_patch.return_value = "good_patch_code"
    mock_engine.generate_exploit.return_value = "exploit_code"

    # Compilation always succeeds
    mock_compile.return_value = "patched_exe"

    mock_save_report.return_value = ("report.json", "report.html")

    run_fuzzer(
        source_path="dummy.c",
        api_key="key",
        gcc_path="gcc",
        max_payloads=1,
        timeout=5,
        debug=False,
        max_patch_retries=2
    )

    # Check that refine_patch was called once
    mock_engine.refine_patch.assert_called_once()
    args, kwargs = mock_engine.refine_patch.call_args
    # Verify content of compile/verification failure details
    assert "The patched binary compiled successfully but still crashed" in args[2]
