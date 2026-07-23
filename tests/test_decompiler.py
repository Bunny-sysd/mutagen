"""
Tests for the Mutagen Decompiler Module.
Tests Ghidra integration, binary detection, and decompilation pipeline.
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mutagen.decompiler import (
    BINARY_EXTENSIONS,
    DecompilationError,
    DecompilationResult,
    _generate_ghidra_postscript,
    _resolve_headless,
    decompile_binary,
    find_ghidra,
    is_binary_target,
)

# =============================================================================
# is_binary_target() tests
# =============================================================================

class TestIsBinaryTarget:
    """Test binary file extension detection."""

    def test_exe_is_binary(self):
        assert is_binary_target("target.exe") is True

    def test_elf_is_binary(self):
        assert is_binary_target("program.elf") is True

    def test_dll_is_binary(self):
        assert is_binary_target("library.dll") is True

    def test_so_is_binary(self):
        assert is_binary_target("libcrypto.so") is True

    def test_o_is_binary(self):
        assert is_binary_target("module.o") is True

    def test_bin_is_binary(self):
        assert is_binary_target("firmware.bin") is True

    def test_sys_is_binary(self):
        assert is_binary_target("driver.sys") is True

    def test_c_is_not_binary(self):
        assert is_binary_target("source.c") is False

    def test_rs_is_not_binary(self):
        assert is_binary_target("main.rs") is False

    def test_cpp_is_not_binary(self):
        assert is_binary_target("app.cpp") is False

    def test_py_is_not_binary(self):
        assert is_binary_target("script.py") is False

    def test_case_insensitive(self):
        assert is_binary_target("TARGET.EXE") is True
        assert is_binary_target("library.DLL") is True

    def test_full_path(self):
        assert is_binary_target("/usr/bin/program.elf") is True
        assert is_binary_target(r"C:\targets\vuln.exe") is True

    def test_no_extension(self):
        assert is_binary_target("program") is False

    def test_all_known_extensions_covered(self):
        """Verify the constant contains expected set."""
        expected = {".exe", ".elf", ".o", ".dll", ".so", ".bin", ".sys"}
        assert BINARY_EXTENSIONS == expected


# =============================================================================
# find_ghidra() tests
# =============================================================================

class TestFindGhidra:
    """Test Ghidra installation auto-detection."""

    def test_explicit_override_valid(self, tmp_path):
        """When a valid --ghidra-path is given, find the headless script."""
        support_dir = tmp_path / "support"
        support_dir.mkdir()
        if sys.platform == "win32":
            headless = support_dir / "analyzeHeadless.bat"
        else:
            headless = support_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash\necho ghidra")

        result = find_ghidra(str(tmp_path))
        assert result == str(headless)

    def test_explicit_override_invalid(self, tmp_path):
        """When an invalid --ghidra-path is given, raise DecompilationError."""
        with pytest.raises(DecompilationError, match="not found at specified path"):
            find_ghidra(str(tmp_path / "nonexistent"))

    @patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ""})
    def test_ghidra_not_installed_raises_error(self):
        """When Ghidra is not found anywhere, raise DecompilationError."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(DecompilationError, match="not installed"):
                find_ghidra("")

    def test_env_variable_detection(self, tmp_path):
        """Detect Ghidra from GHIDRA_INSTALL_DIR env variable."""
        support_dir = tmp_path / "support"
        support_dir.mkdir()
        if sys.platform == "win32":
            headless = support_dir / "analyzeHeadless.bat"
        else:
            headless = support_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash\necho ghidra")

        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(tmp_path)}):
            result = find_ghidra("")
            assert result == str(headless)

    def test_path_detection(self):
        """Detect analyzeHeadless on PATH."""
        fake_path = "/usr/local/bin/analyzeHeadless"
        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ""}):
            with patch("shutil.which", return_value=fake_path):
                result = find_ghidra("")
                assert result == fake_path


# =============================================================================
# _resolve_headless() tests
# =============================================================================

class TestResolveHeadless:
    """Test the internal headless script resolver."""

    def test_finds_script_in_support_dir(self, tmp_path):
        support_dir = tmp_path / "support"
        support_dir.mkdir()
        if sys.platform == "win32":
            script = support_dir / "analyzeHeadless.bat"
        else:
            script = support_dir / "analyzeHeadless"
        script.write_text("echo test")

        assert _resolve_headless(str(tmp_path)) == str(script)

    def test_returns_none_when_not_found(self, tmp_path):
        assert _resolve_headless(str(tmp_path)) is None


# =============================================================================
# _generate_ghidra_postscript() tests
# =============================================================================

class TestGeneratePostscript:
    """Test Ghidra PostScript generation."""

    def test_generates_valid_java(self):
        script = _generate_ghidra_postscript("/tmp/output.c", all_functions=False)
        assert "MutagenExportDecompiled" in script
        assert "extends GhidraScript" in script
        assert "DecompInterface" in script
        assert "/tmp/output.c" in script
        assert "false" in script  # all_functions = false

    def test_all_functions_flag(self):
        script = _generate_ghidra_postscript("/tmp/output.c", all_functions=True)
        # When all_functions=True, the Java code should have "true"
        assert "boolean allFunctions = true" in script

    def test_default_functions_flag(self):
        script = _generate_ghidra_postscript("/tmp/output.c", all_functions=False)
        assert "boolean allFunctions = false" in script


# =============================================================================
# decompile_binary() tests
# =============================================================================

class TestDecompileBinary:
    """Test the main decompilation pipeline."""

    def test_binary_not_found_raises_error(self):
        with pytest.raises(DecompilationError, match="not found"):
            decompile_binary("/nonexistent/binary.exe", "analyzeHeadless")

    def test_successful_decompilation(self, tmp_path):
        """Mock a successful Ghidra run and verify output parsing."""
        binary = tmp_path / "target.exe"
        binary.write_bytes(b"\x4d\x5a" + b"\x00" * 100)  # Minimal PE header

        mock_output = (
            "// ============================================\n"
            "// MUTAGEN DECOMPILED OUTPUT\n"
            "// Binary: target.exe\n"
            "// Format: Portable Executable (PE)\n"
            "// Architecture: x86\n"
            "// Compiler: windows\n"
            "// ============================================\n"
            "\n"
            "// --- Function: main @ 00401000 ---\n"
            "int main(int param_1, char **param_2) {\n"
            "    char local_28[32];\n"
            "    strcpy(local_28, param_2[1]);\n"
            "    return 0;\n"
            "}\n"
            "\n"
            "// --- Total functions decompiled: 1 ---\n"
        )

        # Mock subprocess.run to simulate Ghidra success
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Analysis complete"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            # We need to mock the file output that Ghidra would create
            # Since decompile_binary creates a temp dir, we need to intercept
            original_open = open

            def mock_temp_write(*args, **kwargs):
                """Allow the script file write, mock the output file read."""
                return original_open(*args, **kwargs)

            # Simpler approach: patch tempfile to use our controlled directory
            with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                temp_dir = str(tmp_path / "ghidra_temp")
                os.makedirs(temp_dir, exist_ok=True)
                os.makedirs(os.path.join(temp_dir, "project"), exist_ok=True)

                # Write the mock decompiled output
                output_file = os.path.join(temp_dir, "decompiled_output.c")
                with open(output_file, "w") as f:
                    f.write(mock_output)

                mock_tmpdir.return_value.__enter__ = MagicMock(return_value=temp_dir)
                mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)

                result = decompile_binary(str(binary), "analyzeHeadless")

                assert isinstance(result, DecompilationResult)
                assert result.functions_found == 1
                assert result.architecture == "x86"
                assert result.binary_format == "Portable Executable (PE)"
                assert "strcpy" in result.pseudo_source
                assert result.decompiler_used == "ghidra"

    def test_ghidra_timeout(self, tmp_path):
        """Test that Ghidra timeout raises DecompilationError."""
        binary = tmp_path / "target.exe"
        binary.write_bytes(b"\x4d\x5a" + b"\x00" * 100)

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 120)):
            with pytest.raises(DecompilationError, match="timed out"):
                decompile_binary(str(binary), "analyzeHeadless", timeout=120)

    def test_ghidra_not_executable(self, tmp_path):
        """Test that missing Ghidra binary raises DecompilationError."""
        binary = tmp_path / "target.exe"
        binary.write_bytes(b"\x4d\x5a" + b"\x00" * 100)

        with patch("subprocess.run", side_effect=FileNotFoundError("No such file")):
            with pytest.raises(DecompilationError, match="Could not execute"):
                decompile_binary(str(binary), "/nonexistent/analyzeHeadless")


# =============================================================================
# DecompilationResult tests
# =============================================================================

class TestDecompilationResult:
    """Test the DecompilationResult dataclass."""

    def test_defaults(self):
        result = DecompilationResult()
        assert result.pseudo_source == ""
        assert result.functions_found == 0
        assert result.architecture == "unknown"
        assert result.binary_format == "unknown"
        assert result.binary_path == ""
        assert result.decompiler_used == "ghidra"

    def test_custom_values(self):
        result = DecompilationResult(
            pseudo_source="int main() { return 0; }",
            functions_found=5,
            architecture="x86_64",
            binary_format="ELF",
            binary_path="/tmp/test.elf",
            decompiler_used="ghidra",
        )
        assert result.functions_found == 5
        assert result.architecture == "x86_64"
        assert "main" in result.pseudo_source


# =============================================================================
# Integration: CLI binary routing test
# =============================================================================

class TestCLIBinaryRouting:
    """Test that CLI correctly routes binary targets."""

    def test_binary_extensions_in_ci_mode(self):
        """Verify that is_binary_target is used in CI mode filtering."""
        from mutagen.decompiler import is_binary_target
        # These should be detected as binary targets in CI mode
        assert is_binary_target("vendor/library.dll") is True
        assert is_binary_target("build/output.exe") is True
        # These should NOT be detected as binary
        assert is_binary_target("src/main.c") is False
        assert is_binary_target("lib/mod.rs") is False


# =============================================================================
# ensure_compatible_java_home() tests
# =============================================================================

class TestEnsureCompatibleJavaHome:
    """Test Java version auto-detection and environment resolution."""

    def test_existing_valid_java_home(self):
        """If JAVA_HOME already points to a valid Java 21+, it should not modify it."""
        with patch.dict(os.environ, {"JAVA_HOME": "C:\\fake\\jdk-21"}):
            with patch("os.path.isdir", return_value=True):
                with patch("os.path.exists", return_value=True):
                    # Mock subprocess.run to return Java 21 version output
                    mock_res = MagicMock()
                    mock_res.stderr = 'openjdk version "21.0.1" 2023-10-17'
                    mock_res.stdout = ''
                    with patch("subprocess.run", return_value=mock_res):
                        from mutagen.decompiler import ensure_compatible_java_home
                        ensure_compatible_java_home()
                        assert os.environ["JAVA_HOME"] == "C:\\fake\\jdk-21"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows specific path resolution test")
    def test_invalid_java_home_resolved_from_common_dir(self):
        """If JAVA_HOME is invalid or empty, it should scan system dirs and configure it."""
        with patch.dict(os.environ, {"JAVA_HOME": ""}):
            with patch("os.path.isdir", side_effect=lambda p: "Microsoft" in p or "jdk-21" in p):
                with patch("os.path.exists", return_value=True):
                    # Glob returns our candidate
                    with patch("glob.glob", return_value=["C:\\Program Files\\Microsoft\\jdk-21.0.11-hotspot"]):
                        mock_res = MagicMock()
                        mock_res.stderr = 'openjdk version "21.0.11"'
                        mock_res.stdout = ''
                        with patch("subprocess.run", return_value=mock_res):
                            from mutagen.decompiler import ensure_compatible_java_home
                            ensure_compatible_java_home()
                            assert os.environ["JAVA_HOME"] == "C:\\Program Files\\Microsoft\\jdk-21.0.11-hotspot"

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS specific path resolution test")
    def test_invalid_java_home_resolved_from_common_dir_linux(self):
        """If JAVA_HOME is invalid or empty on Linux/macOS, it should scan system dirs and configure it."""
        with patch.dict(os.environ, {"JAVA_HOME": ""}):
            with patch("os.path.isdir", side_effect=lambda p: "jvm" in p or "jdk-21" in p):
                with patch("os.path.exists", return_value=True):
                    # Glob returns our candidate
                    with patch("glob.glob", return_value=["/usr/lib/jvm/jdk-21.0.11"]):
                        mock_res = MagicMock()
                        mock_res.stderr = 'openjdk version "21.0.11"'
                        mock_res.stdout = ''
                        with patch("subprocess.run", return_value=mock_res):
                            from mutagen.decompiler import ensure_compatible_java_home
                            ensure_compatible_java_home()
                            assert os.environ["JAVA_HOME"] == "/usr/lib/jvm/jdk-21.0.11"

